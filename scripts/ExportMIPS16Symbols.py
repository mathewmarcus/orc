#List MIPS16 ASE function names, entry point addresses, and sizes to a file in CSV format
#@author Mathew Marcus
#@category MIPS
#@keybinding 
#@menupath 
#@toolbar 


import csv

from ghidra.program.model.symbol import SourceType


output_file = askFile("Please Select Output File", "Choose")

program = getCurrentProgram()

with open(output_file.getPath(), "w") as output_file:
    csv_writer = csv.writer(output_file, quoting=csv.QUOTE_ALL)
    csv_writer.writerow(["Name", "Location", "Function Size"])

    for function in program.getFunctionManager().getFunctions(True):
        if function.isThunk():
            continue
        
        addr = function.getEntryPoint()

        sym_type = getSymbolAt(addr).getSource()
        # skip imported functions (SourceType.IMPORTED and SourceType.ANALYSIS)
        if sym_type != SourceType.USER_DEFINED and sym_type != SourceType.DEFAULT:
            continue

        instruction_context = getInstructionAt(addr).getInstructionContext().getProcessorContext()
        isa_mode_register = instruction_context.getRegister("ISA_MODE")
        isa_mode_value = instruction_context.getValue(isa_mode_register, False)

        if isa_mode_value:
            addr = addr.add(isa_mode_value)

        # How to get size of function:
        # https://github.com/NationalSecurityAgency/ghidra/issues/835
        # https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/util/table/field/FunctionBodySizeTableColumn.java#L39
        csv_writer.writerow([function.getName(), addr.toString(), function.getBody().getNumAddresses()])
