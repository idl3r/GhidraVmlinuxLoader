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


// FROM the official skeleton

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

//spec to linux loader

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


import ghidra.app.util.MemoryBlockUtils;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

import java.io.File;
import ghidra.framework.model.Project;
import ghidra.app.util.opinion.Loaded;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GhidraVmlinuxLoader extends BinaryLoader {

	private VmlinuxSymJson symJson;
	private Address startAddress;
	private long startLong;

	static final Logger log4jLogger = LogManager.getLogger(GhidraVmlinuxLoader.class);

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
		// String symFilePathStr = provider.getAbsolutePath();
		File vmlinuxFile = provider.getFile();
		String symFilePathStr = vmlinuxFile.getAbsolutePath();
		symFilePathStr = symFilePathStr.concat(".sym.json");
		log4jLogger.info("Symbol file path: " + symFilePathStr);
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
	protected List<Loaded<Program>> loadProgram(ByteProvider provider, String programName,
			Project project, String programFolderPath, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException {
		log4jLogger.info("Entering loadProgram");

		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec importerCompilerSpec =
			importerLanguage.getCompilerSpecByID(pair.compilerSpecID);

		Address baseAddr =
			importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		Program prog = createProgram(provider, programName, baseAddr, getName(), importerLanguage,
			importerCompilerSpec, consumer);

		startAddress = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(startLong);

		List<Loaded<Program>> loadedList = new ArrayList<Loaded<Program>>();

		log4jLogger.info("Finished creating program");

		boolean success = false;
		try {
			loadInto(provider, loadSpec, options, log, prog, monitor);
			createDefaultMemoryBlocks(prog, importerLanguage, log);
			success = true;
			// return loadedList;
		}
		catch (Exception e) {
			log4jLogger.warn("loadProgram failed with exception: ", e);
		}
		finally {
			if (!success) {
				prog.release(consumer);
				return loadedList;
			}
		}

		FunctionManager funcManager = prog.getFunctionManager();
		SymbolTable symTbl = prog.getSymbolTable();

		int id = prog.startTransaction("Creating Functions");
		boolean commit = true;

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

		prog.endTransaction(id, commit);

		loadedList.add(new Loaded<>(prog, programName, programFolderPath));
		return loadedList;
	}

	@Override
	protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Program prog, TaskMonitor monitor) throws LoadException, IOException {
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
						log,monitor);
				success = true;
				//String msg = mbu.getMessages();
				//if (msg.length() > 0) {
				//	log.appendMsg(msg);
				//}
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
						true,log, monitor);

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
		// return success;
		if (!success) {
			throw new LoadException("Load failed!");
		}

		return;
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
