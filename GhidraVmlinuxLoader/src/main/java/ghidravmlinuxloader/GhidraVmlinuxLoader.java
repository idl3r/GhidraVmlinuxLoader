/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidravmlinuxloader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import ghidra.app.plugin.assembler.sleigh.util.GhidraDBTransaction;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GhidraVmlinuxLoader extends BinaryLoader {

	private VmlinuxSymJson symJson;
	private Address startAddress;
	private long startLong;

	@Override
	public String getName() {
		return "Vmlinux Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		String compiler = "default"; // Only default is supported for now

		// Ghidra requires image base to be determined at this stage, so we need to look
		// for the JSON file here
		String symFilePathStr = provider.getAbsolutePath();
		symFilePathStr = symFilePathStr.concat(".sym.json");
		Path symFilePath = Paths.get(symFilePathStr);
		if (Files.notExists(symFilePath)) {
			return loadSpecs;
		}

		try {
			symJson = VmlinuxSymJson.loadSymJson(symFilePath);
		} catch (Exception e) {
			return loadSpecs;
		}

		LanguageCompilerSpecPair langSpecPair;
		if (symJson.arch.equals("arm")) {
			langSpecPair = new LanguageCompilerSpecPair("ARM:LE:32:v7", compiler);
		} else if (symJson.arch.equals("arm64")) {
			langSpecPair = new LanguageCompilerSpecPair("AARCH64:LE:64:v8A", compiler);
		} else {
			return loadSpecs;
		}

		startLong = Long.parseUnsignedLong(symJson._start.toString(10));

		loadSpecs.add(new LoadSpec(this, startLong, langSpecPair, true));

		return loadSpecs;
	}

	@Override
	protected List<Program> loadProgram(ByteProvider provider, String programName, DomainFolder programFolder,
			LoadSpec loadSpec, List<Option> options, MessageLog log, Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException {
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec importerCompilerSpec = importerLanguage.getCompilerSpecByID(pair.compilerSpecID);
		Address baseAddress = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		List<Program> results = new ArrayList<Program>();
		boolean success = false;

		startAddress = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(startLong);

		Program program = createProgram(provider, programName, baseAddress, getName(), importerLanguage,
				importerCompilerSpec, consumer);

		try {
			success = this.loadInto(provider, loadSpec, options, log, program, monitor);
			if (success) {
				createDefaultMemoryBlocks(program, importerLanguage, log);
			}
		} finally {
			if (!success) {
				program.release(consumer);
				return results;
			}
		}

		GhidraDBTransaction trans = new GhidraDBTransaction(program, "Vmlinux Loader");
		FunctionManager funcManager = program.getFunctionManager();
		SymbolTable symTbl = program.getSymbolTable();

		for (int i = 0; i < symJson.address.length; i++) {
			long symAddressLong = Long.parseUnsignedLong(symJson.address[i].toString(10));
			Address symAddress = importerLanguage.getAddressFactory().getDefaultAddressSpace()
					.getAddress(symAddressLong);
			String type = symJson.type[i];
			String name = symJson.name[i];

			if (type.equals("T") || type.equals("t")) {
				AddressSet symAddrSet = new AddressSet(symAddress);
				try {
					funcManager.createFunction(name, symAddress, symAddrSet, SourceType.IMPORTED);
				} catch (InvalidInputException e) {
				} catch (OverlappingFunctionException e) {
				}
			} else {
				try {
					symTbl.createLabel(symAddress, name, SourceType.IMPORTED);
				} catch (InvalidInputException e) {
				}
			}
		}

		trans.commit();
		trans.close();

		results.add(program);

		return results;
	}

	@Override
	protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Program prog, TaskMonitor monitor) throws IOException {
		long length = provider.length();
		long fileOffset = 0;
		Address baseAddr = startAddress;
		String blockName = null;
		boolean isOverlay = false;

		MemoryBlockUtils mbu = new MemoryBlockUtils();

		boolean success = false;

		// Briefly divide the memory block into two parts
		// .text: Code and some rodata
		// .data: RW data
		// This depends on symbol '_sinittext'
		int idxStartInitText = 0;

		for (int i = 0; i < symJson.address.length; i++) {
			if (symJson.name[i].equals("_sinittext")) {
				idxStartInitText = i;
				break;
			}
		}

		if (idxStartInitText == 0) {
			try (InputStream fis = provider.getInputStream(fileOffset)) {
				blockName = generateBlockName(prog, isOverlay, baseAddr.getAddressSpace());
				mbu.createInitializedBlock(prog, isOverlay, blockName, baseAddr, fis, length,
						"fileOffset=" + fileOffset + ", length=" + length, provider.getAbsolutePath(), true, true, true,
						log, monitor);
				success = true;
			} catch (AddressOverflowException e) {
				throw new IllegalArgumentException("Invalid address range specified: start:" + baseAddr + ", length:"
						+ length + " - end address exceeds address space boundary!");
			}
		} else {
			try {
				InputStream fis;

				long sInitTextLong = Long.parseUnsignedLong(symJson.address[idxStartInitText].toString(10));

				fileOffset = 0;
				length = sInitTextLong - startLong;
				fis = provider.getInputStream(0);
				blockName = ".text";
				mbu.createInitializedBlock(prog, isOverlay, blockName, baseAddr, fis, length,
						"fileOffset=" + fileOffset + ", length=" + length, provider.getAbsolutePath(), true, false,
						true, log, monitor);

				fileOffset = length;
				length = provider.length() - fileOffset;
				fis = provider.getInputStream(fileOffset);
				blockName = ".data";
				mbu.createInitializedBlock(prog, isOverlay, blockName, baseAddr.add(fileOffset), fis, length,
						"fileOffset=" + fileOffset + ", length=" + length, provider.getAbsolutePath(), true, true, true,
						log, monitor);

				success = true;
			} catch (AddressOverflowException e) {
				throw new IllegalArgumentException("Invalid address range specified: start:" + baseAddr + ", length:"
						+ length + " - end address exceeds address space boundary!");
			}
		}
		return success;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
