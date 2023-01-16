#List MIPS16 ASE function names, entry point addresses, and sizes to a file in CSV format
#@author Mathew Marcus
#@category MIPS
#@keybinding 
#@menupath 
#@toolbar 


import csv

from ghidra.program.model.symbol import SourceType


output_file = askFile("Please Select Output File", "Choose")

# This is necessary when exporting functions for shared objects,
# which will already include a dynamic symbol table
# Limiting the export to user-defined functions in those cases
# will prevent the creation of duplicate symbols
user_defined_only = askYesNo("Please Select Function Type", "User-Defined functions only?")
program = getCurrentProgram()

with open(output_file.getPath(), "w") as output_file:
    csv_writer = csv.writer(output_file, quoting=csv.QUOTE_ALL)
    csv_writer.writerow(["Name", "Location", "Function Size"])

    for function in program.getFunctionManager().getFunctions(True):
        if function.isThunk():
            continue
        
        addr = function.getEntryPoint()

        if user_defined_only and getSymbolAt(addr).getSource() != SourceType.USER_DEFINED:
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
