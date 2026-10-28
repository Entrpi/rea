import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * The Xtensa call0 ABI preserves a12-a15 across a call and lets the callee change a8-a11.
 * Ghidra 12.1.4's xtensa.cspec defines that as the `__call0` prototype, but its default
 * prototype models windowed calls, and a program cannot replace the default: the Decompiler
 * "Prototype Evaluation" option selects only the model of the function being decompiled. After
 * analysis, assign `__call0` to every function, external function and function definition, so
 * each call to them has the call0 register effects. A thunk takes its target's convention.
 */
public final class ReaGhidraXtensaCall0 extends GhidraScript {
  static final String REPORT_KEY = "REA Xtensa call0 prototype";
  static final String POLICY = "call0-prototype-v1";
  static final String PROTOTYPE = "__call0";

  @Override
  public void run() throws Exception {
    String processor = currentProgram.getLanguage().getProcessor().toString();
    if (!processor.equals("Xtensa"))
      throw new IllegalStateException(
          "REA call0 prototype requires an Xtensa program, not " + processor);
    if (currentProgram.getCompilerSpec().getCallingConvention(PROTOTYPE) == null)
      throw new IllegalStateException(
          "The compiler specification of this program defines no " + PROTOTYPE + " prototype");
    List<Function> callables = new ArrayList<>();
    currentProgram.getFunctionManager().getFunctions(true).forEach(callables::add);
    currentProgram.getFunctionManager().getExternalFunctions().forEach(callables::add);
    int functions = 0;
    for (Function function : callables) {
      if (function.isThunk()) continue;
      function.setCallingConvention(PROTOTYPE);
      if (!PROTOTYPE.equals(function.getCallingConventionName()))
        throw new IllegalStateException(
            "REA call0 prototype did not apply to " + function.getName(true));
      functions += 1;
    }
    int definitions = 0;
    Iterator<DataType> types = currentProgram.getDataTypeManager().getAllDataTypes();
    while (types.hasNext()) {
      if (!(types.next() instanceof FunctionDefinition definition)) continue;
      definition.setCallingConvention(PROTOTYPE);
      definitions += 1;
    }
    // Written last: any failure above leaves no report, and REA refuses the session.
    currentProgram.getOptions(Program.PROGRAM_INFO).setString(
        REPORT_KEY,
        "{\"policy\":\"" + POLICY + "\",\"functions\":" + functions +
            ",\"definitions\":" + definitions + "}");
    println("REA Xtensa call0 prototype: functions=" + functions + " definitions=" + definitions);
  }
}
