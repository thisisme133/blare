/* ###
 * IP: PUBLIC DOMAIN
 *
 * Export Control Flow Graph (functions, basic blocks, edges, indirect targets)
 * to JSON for use by the remill lifter pipeline. Run as a Ghidra headless
 * postScript after analysis.
 *
 * Usage (headless):
 *   analyzeHeadless /path/to/project ProjectName -import game.exe \
 *     -postScript ExportCFG.java output.json
 *
 * Script args: first argument is the output JSON file path (required in headless).
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public class ExportCFG extends GhidraScript {

    private static String addrToString(Address addr) {
        return addr == null ? null : "0x" + Long.toUnsignedString(addr.getOffset(), 16);
    }

    private static int readU16LE(byte[] bytes, int off) {
        return (bytes[off] & 0xff) | ((bytes[off + 1] & 0xff) << 8);
    }

    private static long readU32LE(byte[] bytes, int off) {
        return (bytes[off] & 0xffL)
            | ((bytes[off + 1] & 0xffL) << 8)
            | ((bytes[off + 2] & 0xffL) << 16)
            | ((bytes[off + 3] & 0xffL) << 24);
    }

    private static long readU64LE(byte[] bytes, int off) {
        return (bytes[off] & 0xffL)
            | ((bytes[off + 1] & 0xffL) << 8)
            | ((bytes[off + 2] & 0xffL) << 16)
            | ((bytes[off + 3] & 0xffL) << 24)
            | ((bytes[off + 4] & 0xffL) << 32)
            | ((bytes[off + 5] & 0xffL) << 40)
            | ((bytes[off + 6] & 0xffL) << 48)
            | ((bytes[off + 7] & 0xffL) << 56);
    }

    private static String readPeImageBaseFromExecutable(Program program) {
        try {
            String executablePath = program.getExecutablePath();
            if (executablePath == null || executablePath.isEmpty()) {
                return null;
            }

            byte[] bytes = Files.readAllBytes(new File(executablePath).toPath());
            if (bytes.length < 0x100) {
                return null;
            }
            if (bytes[0] != 'M' || bytes[1] != 'Z') {
                return null;
            }

            int peOff = (int) readU32LE(bytes, 0x3c);
            int optionalOff = peOff + 4 + 20;
            if (peOff < 0 || optionalOff + 32 > bytes.length) {
                return null;
            }
            if (bytes[peOff] != 'P' || bytes[peOff + 1] != 'E' || bytes[peOff + 2] != 0 || bytes[peOff + 3] != 0) {
                return null;
            }

            int magic = readU16LE(bytes, optionalOff);
            if (magic != 0x20b) {
                return null;
            }
            long imageBase = readU64LE(bytes, optionalOff + 24);
            return "0x" + Long.toUnsignedString(imageBase, 16);
        } catch (Exception ignored) {
            return null;
        }
    }

    private Map<String, JumpTableMeta> collectJumpTableMetaForFunction(DecompInterface decompiler, Function func) {
        LinkedHashMap<String, JumpTableMeta> bySite = new LinkedHashMap<>();
        try {
            DecompileResults results = decompiler.decompileFunction(func, 60, getMonitor());
            if (!results.decompileCompleted()) {
                return bySite;
            }

            HighFunction high = results.getHighFunction();
            if (high == null) {
                return bySite;
            }

            JumpTable[] jumpTables = high.getJumpTables();
            if (jumpTables == null) {
                return bySite;
            }

            for (JumpTable jumpTable : jumpTables) {
                String site = addrToString(jumpTable.getSwitchAddress());
                if (site == null) {
                    continue;
                }

                JumpTableMeta meta = new JumpTableMeta();

                JumpTable.LoadTable[] addressTables = jumpTable.getLoadTables();
                if (addressTables != null && addressTables.length > 0 && addressTables[0] != null) {
                    Address base = addressTables[0].getAddress();
                    if (base != null) {
                        meta.base = addrToString(base);
                    }
                    int size = addressTables[0].getSize();
                    if (size > 0 && size <= 16) {
                        meta.entry_size = size;
                    }
                }

                Integer[] labels = jumpTable.getLabelValues();
                if (labels != null && labels.length > 0) {
                    long min = labels[0].longValue();
                    long max = labels[0].longValue();
                    for (Integer label : labels) {
                        if (label == null) {
                            continue;
                        }
                        long value = label.longValue();
                        min = Math.min(min, value);
                        max = Math.max(max, value);
                    }
                    meta.min_index = min;
                    meta.max_index = max;
                }

                bySite.put(site, meta);
            }
        } catch (Exception ignored) {
            // Best effort only: keep exporting even if decompilation metadata is unavailable.
        }
        return bySite;
    }

    @Override
    public void run() throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            printerr("No current program.");
            return;
        }

        String[] args = getScriptArgs();
        String outputPath = (args != null && args.length > 0) ? args[0] : null;
        if (outputPath == null || outputPath.isEmpty()) {
            printerr("Usage: ExportCFG.java <output.json>");
            return;
        }

        File outFile = new File(outputPath);
        if (outFile.getParentFile() != null) {
            outFile.getParentFile().mkdirs();
        }

        SimpleBlockModel blockModel = new SimpleBlockModel(program);
        FunctionManager functionManager = program.getFunctionManager();

        CfgOutput output = new CfgOutput();
        output.program_name = program.getDomainFile().getName();
        String originalImageBase = readPeImageBaseFromExecutable(program);
        output.image_base = originalImageBase != null ? originalImageBase : addrToString(program.getImageBase());
        output.functions = new ArrayList<>();

        LinkedHashMap<String, List<CodeBlock>> blocksByFunctionEntry = new LinkedHashMap<>();
        CodeBlockIterator allBlocks = blockModel.getCodeBlocks(getMonitor());
        while (allBlocks.hasNext()) {
            CodeBlock block;
            try {
                block = allBlocks.next();
            } catch (CancelledException e) {
                break;
            }
            Address blockStart = block.getFirstStartAddress();
            if (blockStart == null) {
                continue;
            }
            Function owner = functionManager.getFunctionContaining(blockStart);
            if (owner == null) {
                continue;
            }
            String ownerKey = addrToString(owner.getEntryPoint());
            blocksByFunctionEntry.computeIfAbsent(ownerKey, k -> new ArrayList<>()).add(block);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        decompiler.toggleCCode(false);
        decompiler.toggleSyntaxTree(false);
        decompiler.setSimplificationStyle("normalize");
        boolean decompilerReady = decompiler.openProgram(program);

        Iterator<Function> funcIter = functionManager.getFunctions(true);
        try {
            while (funcIter.hasNext()) {
                Function func = funcIter.next();

                List<CodeBlock> blocks = blocksByFunctionEntry.get(addrToString(func.getEntryPoint()));
                if (blocks == null || blocks.isEmpty()) {
                    continue;
                }
                blocks.sort((a, b) -> Long.compareUnsigned(
                    a.getFirstStartAddress().getOffset(),
                    b.getFirstStartAddress().getOffset()
                ));

                FunctionCfg fc = new FunctionCfg();
                fc.name = func.getName();
                fc.address = addrToString(func.getEntryPoint());
                fc.blocks = new ArrayList<>();
                fc.edges = new ArrayList<>();
                fc.indirect_sites = new ArrayList<>();
                fc.jump_tables = new ArrayList<>();

                LinkedHashMap<String, IndirectSiteAcc> indirectSitesByKey = new LinkedHashMap<>();
                LinkedHashMap<String, LinkedHashSet<String>> jumpTableTargetsBySite = new LinkedHashMap<>();

                for (CodeBlock block : blocks) {
                    Block b = new Block();
                    b.start = addrToString(block.getFirstStartAddress());
                    // end is exclusive (first address after the block)
                    b.end = addrToString(block.getMaxAddress().add(1));
                    fc.blocks.add(b);
                }

                for (CodeBlock block : blocks) {
                    CodeBlockReferenceIterator destIter = block.getDestinations(getMonitor());
                    while (destIter.hasNext()) {
                        CodeBlockReference ref;
                        try {
                            ref = destIter.next();
                        } catch (CancelledException e) {
                            break;
                        }
                        FlowType flowType = ref.getFlowType();
                        String edgeType = "branch";
                        if (flowType.isCall()) edgeType = "call";
                        else if (flowType.isFallthrough()) edgeType = "fallthrough";

                        Edge e = new Edge();
                        e.from = addrToString(block.getFirstStartAddress());
                        e.to = addrToString(ref.getDestinationAddress());
                        e.type = edgeType;
                        if (flowType.isComputed() && !flowType.isCall()) e.indirect = true;
                        fc.edges.add(e);

                        if (flowType.isComputed() && ref.getReferent() != null) {
                            String site = addrToString(ref.getReferent());
                            String kind = flowType.isCall() ? "call" : "jump";
                            String key = site + "|" + kind;

                            IndirectSiteAcc acc = indirectSitesByKey.get(key);
                            if (acc == null) {
                                acc = new IndirectSiteAcc();
                                acc.address = site;
                                acc.kind = kind;
                                acc.possible_targets = new LinkedHashSet<>();
                                indirectSitesByKey.put(key, acc);
                            }

                            String destination = addrToString(ref.getDestinationAddress());
                            if (destination != null) {
                                acc.possible_targets.add(destination);
                            }

                            if (!flowType.isCall() && destination != null) {
                                LinkedHashSet<String> targets = jumpTableTargetsBySite.get(site);
                                if (targets == null) {
                                    targets = new LinkedHashSet<>();
                                    jumpTableTargetsBySite.put(site, targets);
                                }
                                targets.add(destination);
                            }
                        }
                    }
                }

                for (IndirectSiteAcc acc : indirectSitesByKey.values()) {
                    IndirectSiteCfg site = new IndirectSiteCfg();
                    site.address = acc.address;
                    site.kind = acc.kind;
                    site.possible_targets = new ArrayList<>(acc.possible_targets);
                    fc.indirect_sites.add(site);
                }

                Map<String, JumpTableMeta> jumpTableMetaBySite = new LinkedHashMap<>();
                if (decompilerReady && !jumpTableTargetsBySite.isEmpty()) {
                    jumpTableMetaBySite = collectJumpTableMetaForFunction(decompiler, func);
                }
                for (Map.Entry<String, LinkedHashSet<String>> jumpEntry : jumpTableTargetsBySite.entrySet()) {
                    JumpTableCfg jt = new JumpTableCfg();
                    jt.site = jumpEntry.getKey();
                    JumpTableMeta meta = jumpTableMetaBySite.get(jumpEntry.getKey());
                    jt.base = meta != null ? meta.base : null;
                    jt.entry_size = meta != null ? meta.entry_size : null;
                    jt.min_index = meta != null ? meta.min_index : null;
                    jt.max_index = meta != null ? meta.max_index : null;
                    jt.targets = new ArrayList<>(jumpEntry.getValue());
                    fc.jump_tables.add(jt);
                }

                output.functions.add(fc);
            }
        } finally {
            decompiler.dispose();
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(output);
        Files.write(outFile.toPath(), json.getBytes(StandardCharsets.UTF_8));
        println("CFG written to " + outFile.getAbsolutePath());
    }

    private static class CfgOutput {
        String program_name;
        String image_base;
        List<FunctionCfg> functions;
    }

    private static class FunctionCfg {
        String name;
        String address;
        List<Block> blocks;
        List<Edge> edges;
        List<IndirectSiteCfg> indirect_sites;
        List<JumpTableCfg> jump_tables;
    }

    private static class Block {
        String start;
        String end;
    }

    private static class Edge {
        String from;
        String to;
        String type;
        Boolean indirect;
    }

    private static class IndirectSiteAcc {
        String address;
        String kind;
        LinkedHashSet<String> possible_targets;
    }

    private static class IndirectSiteCfg {
        String address;
        String kind;
        List<String> possible_targets;
    }

    private static class JumpTableMeta {
        String base;
        Integer entry_size;
        Long min_index;
        Long max_index;
    }

    private static class JumpTableCfg {
        String site;
        String base;
        Integer entry_size;
        Long min_index;
        Long max_index;
        List<String> targets;
    }
}
