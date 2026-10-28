import ghidra.app.script.GhidraScript;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.XmlEncode;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**
 * Apply the committed RISC-V calling-convention policy after analysis. Ghidra's generic RV32
 * compiler specification models ilp32d. The ilp32 policy derives a program-specific prototype from
 * the program's own default prototype: it removes every floating-point argument and return entry
 * and every rule that places a value in floating-point storage, and it moves fs0-fs11 from the
 * preserved registers to the registers killed by calls. The script installs the prototype as a
 * specification extension and assigns it, with dynamic storage, to every non-thunk function,
 * external function and function definition. docs/ghidra-riscv.md states the policy.
 */
public final class ReaGhidraRiscvCallingConvention extends GhidraScript {
  static final String REPORT_KEY = "REA RISC-V calling convention";
  static final String ILP32_POLICY = "ilp32-prototype-v1";
  static final String ILP32_PROTOTYPE = "__rea_ilp32";
  /** RISC-V floating-point registers by ABI name: ft0-ft11, fs0-fs11 and fa0-fa7. */
  private static final Pattern FLOAT_REGISTER = Pattern.compile("f[ast]\\d+");

  @Override
  public void run() throws Exception {
    String[] arguments = getScriptArgs();
    if (arguments.length != 1 || !arguments[0].equals(ILP32_POLICY))
      throw new IllegalArgumentException(
          "REA RISC-V calling convention requires the policy " + ILP32_POLICY);
    Language language = currentProgram.getLanguage();
    if (!language.getProcessor().toString().equals("RISCV")
        || currentProgram.getDefaultPointerSize() != 4)
      throw new IllegalStateException(
          "REA ilp32 prototype requires a 32-bit RISC-V program, not " + language.getLanguageID());
    CompilerSpec spec = currentProgram.getCompilerSpec();
    new SpecExtension(currentProgram)
        .addReplaceCompilerSpecExtension(
            ilp32Prototype(spec.getDefaultCallingConvention(), spec, language), monitor);
    PrototypeModel ilp32 = currentProgram.getCompilerSpec().getCallingConvention(ILP32_PROTOTYPE);
    if (ilp32 == null) throw new IllegalStateException("REA ilp32 prototype was not installed");
    StructureDataType pair = new StructureDataType("rea_ilp32_float_pair", 0);
    pair.add(FloatDataType.dataType);
    pair.add(FloatDataType.dataType);
    requireIntegerStorage(
        ilp32.getStorageLocations(
            currentProgram,
            new DataType[] {
              DoubleDataType.dataType, FloatDataType.dataType, DoubleDataType.dataType,
              IntegerDataType.dataType, pair, FloatDataType.dataType
            },
            false),
        "ilp32 prototype self-check",
        false);
    for (Varnode preserved : ilp32.getUnaffectedList()) {
      Register register = language.getRegister(preserved.getAddress(), preserved.getSize());
      if (register != null && FLOAT_REGISTER.matcher(register.getName()).matches())
        throw new IllegalStateException("REA ilp32 prototype still preserves " + register.getName());
    }
    int functions = 0;
    List<Function> callables = new ArrayList<>();
    currentProgram.getFunctionManager().getFunctions(true).forEach(callables::add);
    currentProgram.getFunctionManager().getExternalFunctions().forEach(callables::add);
    for (Function function : callables) {
      // A thunk's signature is its target's; the target is in this list.
      if (function.isThunk()) continue;
      if (function.hasCustomVariableStorage()) function.setCustomVariableStorage(false);
      function.setCallingConvention(ILP32_PROTOTYPE);
      List<VariableStorage> storage = new ArrayList<>();
      storage.add(function.getReturn().getVariableStorage());
      for (Parameter parameter : function.getParameters()) storage.add(parameter.getVariableStorage());
      // An untyped function has no assigned storage yet; the decompiler applies the
      // prototype when it recovers one.
      requireIntegerStorage(
          storage.toArray(VariableStorage[]::new), function.getName(true), true);
      functions += 1;
    }
    int definitions = 0;
    Iterator<DataType> types = currentProgram.getDataTypeManager().getAllDataTypes();
    while (types.hasNext()) {
      if (!(types.next() instanceof FunctionDefinition definition)) continue;
      definition.setCallingConvention(ILP32_PROTOTYPE);
      definitions += 1;
    }
    // Written last: any failure above leaves no report, and REA refuses the session.
    currentProgram.getOptions(Program.PROGRAM_INFO).setString(
        REPORT_KEY,
        "{\"policy\":\"" + ILP32_POLICY + "\",\"functions\":" + functions
            + ",\"definitions\":" + definitions + "}");
    println("REA RISC-V ilp32 prototype: functions=" + functions + " definitions=" + definitions);
  }

  /** The default ilp32d prototype without floating-point storage, preserving no FP register. */
  private static String ilp32Prototype(PrototypeModel base, CompilerSpec spec, Language language)
      throws Exception {
    XmlEncode encoder = new XmlEncode();
    base.encode(encoder, spec.getPcodeInjectLibrary());
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    Document document =
        factory.newDocumentBuilder().parse(new InputSource(new StringReader(encoder.toString())));
    Element root = document.getDocumentElement();
    if (!root.getTagName().equals("prototype"))
      throw new IllegalStateException("Unexpected default prototype encoding " + root.getTagName());
    root.setAttribute("name", ILP32_PROTOTYPE);
    List<Node> removed = new ArrayList<>();
    NodeList entries = root.getElementsByTagName("pentry");
    for (int index = 0; index < entries.getLength(); index += 1) {
      Element entry = (Element) entries.item(index);
      if (entry.getAttribute("storage").equals("float")) removed.add(entry);
    }
    int floatEntries = removed.size();
    NodeList rules = root.getElementsByTagName("rule");
    for (int index = 0; index < rules.getLength(); index += 1) {
      Element rule = (Element) rules.item(index);
      if (usesFloatStorage(rule)) removed.add(rule);
    }
    if (floatEntries == 0 || removed.size() == floatEntries)
      throw new IllegalStateException(
          "Default prototype has no floating-point entries or rules to remove");
    for (Node node : removed) node.getParentNode().removeChild(node);
    NodeList killedLists = root.getElementsByTagName("killedbycall");
    Element killed = killedLists.getLength() == 0 ? null : (Element) killedLists.item(0);
    if (killed == null) {
      killed = document.createElement("killedbycall");
      root.appendChild(killed);
    }
    List<Element> moved = new ArrayList<>();
    NodeList preservedLists = root.getElementsByTagName("unaffected");
    for (int list = 0; list < preservedLists.getLength(); list += 1) {
      NodeList preserved = preservedLists.item(list).getChildNodes();
      for (int index = 0; index < preserved.getLength(); index += 1) {
        if (preserved.item(index) instanceof Element varnode && isFloatRegister(varnode, language))
          moved.add(varnode);
      }
    }
    for (Element varnode : moved) {
      varnode.getParentNode().removeChild(varnode);
      killed.appendChild(varnode);
    }
    StringWriter xml = new StringWriter();
    var transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.transform(new DOMSource(document), new StreamResult(xml));
    return xml.toString();
  }

  /** Whether a rule's action, at any depth, assigns floating-point storage. */
  private static boolean usesFloatStorage(Element element) {
    NodeList children = element.getChildNodes();
    for (int index = 0; index < children.getLength(); index += 1) {
      if (!(children.item(index) instanceof Element child)) continue;
      if (child.getAttribute("storage").equals("float") || usesFloatStorage(child)) return true;
    }
    return false;
  }

  private static boolean isFloatRegister(Element varnode, Language language) {
    if (!varnode.getTagName().equals("varnode")
        || !varnode.getAttribute("space").equals("register"))
      return false;
    Register register =
        language.getRegister(
            language.getAddressFactory().getRegisterSpace()
                .getAddress(Long.decode(varnode.getAttribute("offset"))),
            Integer.parseInt(varnode.getAttribute("size")));
    return register != null && FLOAT_REGISTER.matcher(register.getName()).matches();
  }

  private static void requireIntegerStorage(
      VariableStorage[] storage, String owner, boolean allowUnassigned) {
    for (VariableStorage item : storage) {
      if (item.isBadStorage() || (!allowUnassigned && item.isUnassignedStorage()))
        throw new IllegalStateException("REA ilp32 storage unresolved for " + owner);
      List<Register> registers = item.getRegisters();
      if (registers == null) continue; // stack-only storage
      for (Register register : registers) {
        if (FLOAT_REGISTER.matcher(register.getName()).matches())
          throw new IllegalStateException(
              "REA ilp32 storage still uses " + register.getName() + " for " + owner);
      }
    }
  }
}
