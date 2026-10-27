import com.google.gson.JsonObject;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Program;

/**
 * Set the DWARF analyzer's default calling convention before default
 * auto-analysis, so the function signatures that DWARF describes use the named
 * prototype of this program's compiler specification. REA names Ghidra's own
 * __stdcall_softfp for ARM images that declare the base (soft-float)
 * procedure-call standard.
 *
 * Ghidra registers the DWARF analyzer only for a program that carries DWARF,
 * so the setting does not apply to a stripped image. The outcome is stored as
 * a program property that the bridge reports during its handshake; a failure
 * leaves no report, and REA refuses the session.
 */
public final class ReaGhidraDwarfCallingConvention extends HeadlessScript {
    static final String REPORT_OPTION = "REA DWARF calling convention";
    private static final String ANALYZER = "DWARF";
    private static final String OPTION = ANALYZER + ".Default Calling Convention";

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1 || arguments[0].isBlank()) {
            throw new IllegalArgumentException(
                "ReaGhidraDwarfCallingConvention requires one calling convention name");
        }
        String name = arguments[0];
        if (currentProgram.getCompilerSpec().getCallingConvention(name) == null) {
            throw new IllegalStateException(
                "The compiler specification of this program defines no " + name + " prototype");
        }
        String status = "not_applicable";
        if (AutoAnalysisManager.getAnalysisManager(currentProgram).getAnalyzer(ANALYZER) != null) {
            if (!getCurrentAnalysisOptionsAndValues(currentProgram).containsKey(OPTION)) {
                throw new IllegalStateException("Ghidra registered the " + ANALYZER +
                    " analyzer for this program without the " + OPTION + " option");
            }
            setAnalysisOption(currentProgram, OPTION, name);
            if (!name.equals(getCurrentAnalysisOptionsAndValues(currentProgram).get(OPTION))) {
                throw new IllegalStateException("The " + OPTION + " option did not take " + name);
            }
            status = "applied";
        }
        JsonObject report = new JsonObject();
        report.addProperty("calling_convention", name);
        report.addProperty("status", status);
        currentProgram.getOptions(Program.PROGRAM_INFO).setString(REPORT_OPTION, report.toString());
        println("REA DWARF calling convention: " + report);
    }
}
