import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighCompilerSpecDescription;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.SleighLanguageDescription;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Seed the caller-supplied raw-binary entry before default auto-analysis. */
public final class ReaGhidraPrepareRaw extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 4 && arguments.length != 5) {
            throw new IllegalArgumentException(
                "Raw binary preparation requires the committed language, load base, entry and entry context, " +
                    "and the committed definition of a caller-selected language"
            );
        }
        String expectedLanguage = arguments[0];
        String baseHex = arguments[1];
        String entryHex = arguments[2];
        String entryContext = arguments[3];
        if (!currentProgram.getLanguageID().getIdAsString().equals(expectedLanguage) ||
            !currentProgram.getExecutableFormat().equals("Raw Binary")) {
            throw new IllegalArgumentException(
                "Raw binary preparation requires the committed language and BinaryLoader import"
            );
        }
        if (arguments.length == 5) {
            requireCommittedDefinition(expectedLanguage, arguments[4]);
        }
        Address base = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(baseHex);
        Address entry = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(entryHex);
        MemoryBlock block = base == null ? null : currentProgram.getMemory().getBlock(base);
        boolean fileStart = false;
        if (block != null) {
            // Processor-defined zero page/stack blocks can precede the imported file.
            for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
                if (source.getFileBytes().isPresent() && source.getFileBytesOffset() == 0 &&
                    base.equals(source.getMinAddress())) {
                    fileStart = true;
                    break;
                }
            }
        }
        if (!fileStart) {
            throw new IllegalArgumentException(
                "Raw binary import must map file offset 0 at the committed load base"
            );
        }
        if (entry == null || !block.contains(entry)) {
            throw new IllegalArgumentException("Raw binary entry must lie inside the source-backed load block");
        }
        if (!entryContext.equals("language-default")) {
            // The committed language selects this context; refuse to analyze if it does not.
            String[] assignment = entryContext.split("=", 2);
            if (assignment.length != 2 || !assignment[1].startsWith("0x")) {
                throw new IllegalArgumentException("Raw binary entry context must be language-default or REGISTER=0xVALUE");
            }
            Register register = currentProgram.getRegister(assignment[0]);
            BigInteger expected = new BigInteger(assignment[1].substring(2), 16);
            if (register == null ||
                !expected.equals(currentProgram.getProgramContext().getValue(register, entry, false))) {
                throw new IllegalStateException("Raw binary entry context " + entryContext + " is not in effect at the entry");
            }
        }
        addEntryPoint(entry);
        if (!disassemble(entry) || createFunction(entry, "entry") == null) {
            throw new IllegalStateException("Raw binary entry cannot be decoded as a function");
        }
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA raw binary prepared", true);
    }

    /**
     * A caller-selected language must be the definition REA committed, and one
     * whose default space is byte-addressed, as wide as declared, and the only
     * loaded memory space. Ghidra recompiles a stale .sla it can write while
     * loading the language, which changes the digest REA committed.
     */
    private void requireCommittedDefinition(String language, String committed) throws Exception {
        Map<String, String> values = new LinkedHashMap<>();
        for (String item : committed.split(";")) {
            String[] assignment = item.split("=", 2);
            if (assignment.length != 2 || values.put(assignment[0], assignment[1]) != null) {
                throw new IllegalArgumentException("Raw binary language definition must be KEY=VALUE pairs");
            }
        }
        if (!values.keySet().equals(Set.of("bits", "ldefs", "sla", "pspec", "cspec"))) {
            throw new IllegalArgumentException("Raw binary language definition must name bits, ldefs, sla, pspec and cspec");
        }
        LanguageDescription description = currentProgram.getLanguage().getLanguageDescription();
        CompilerSpecDescription compiler = currentProgram.getCompilerSpec().getCompilerSpecDescription();
        if (!(description instanceof SleighLanguageDescription sleigh) ||
            !(compiler instanceof SleighCompilerSpecDescription cspec)) {
            throw new IllegalStateException("Raw binary language " + language + " is not a SLEIGH language definition");
        }
        requireDigest(language, "ldefs", sleigh.getDefsFile(), values.get("ldefs"));
        requireDigest(language, "sla", sleigh.getSlaFile(), values.get("sla"));
        requireDigest(language, "pspec", sleigh.getSpecFile(), values.get("pspec"));
        requireDigest(language, "cspec", cspec.getFile(), values.get("cspec"));
        AddressSpace space = currentProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();
        int bits = Integer.parseInt(values.get("bits"));
        if (space.getAddressableUnitSize() != 1) {
            throw new IllegalStateException(
                "Raw binary language " + language + " has a default address space " + space.getName() +
                    " that is not byte-addressed"
            );
        }
        if (space.getSize() != bits) {
            throw new IllegalStateException(
                "Raw binary language " + language + " has a " + space.getSize() + "-bit default address space " +
                    space.getName() + ", not the " + bits + " bits its .ldefs entry declares"
            );
        }
        List<String> loaded = new ArrayList<>();
        for (AddressSpace candidate : currentProgram.getLanguage().getAddressFactory().getAllAddressSpaces()) {
            if (candidate.isLoadedMemorySpace()) {
                loaded.add(candidate.getName());
            }
        }
        if (!loaded.equals(List.of(space.getName()))) {
            throw new IllegalStateException(
                "Raw binary language " + language + " has loaded memory spaces " + loaded +
                    "; REA admits a caller-selected language only when its default space is the only one"
            );
        }
    }

    private static void requireDigest(String language, String role, ResourceFile file, String expected)
        throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = file.getInputStream()) {
            byte[] buffer = new byte[65536];
            for (int count = input.read(buffer); count >= 0; count = input.read(buffer)) {
                digest.update(buffer, 0, count);
            }
        }
        String observed = HexFormat.of().formatHex(digest.digest());
        if (!observed.equals(expected)) {
            throw new IllegalStateException(
                "Raw binary language " + language + " loaded " + role + " file " + file.getName() +
                    " with SHA-256 " + observed + ", not the committed " + expected +
                    "; the definition changed after REA resolved it, so reopen the target"
            );
        }
    }
}
