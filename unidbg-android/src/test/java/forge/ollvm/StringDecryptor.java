package forge.ollvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class StringDecryptor {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Map<Long, byte[]> modifyMap = new HashMap<>();
    private final Map<Long, byte[]> mergedMap = new HashMap<>();
    private Module targetModule;

    public StringDecryptor() {
        emulator = AndroidEmulatorBuilder.for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setRootDir(new File("unidbg-android/src/test/resources/android"))
                .build();

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23)); // 设置Android API版本

        // 创建Dalvik虚拟机
        vm = emulator.createDalvikVM();
        vm.setVerbose(true); // 开启详细日志

        // 提前设置内存写入Hook
        emulator.getBackend().hook_add_new(new WriteHook() {
            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }

            @Override
            public void hook(Backend backend, long address, int size, long value, Object user) {
                // 记录所有内存写入
                byte[] bytes = longToBytes(value, size);
                modifyMap.put(address, bytes);
                System.out.printf("Memory write at 0x%x, size=%d, value=0x%x%n", address, size, value);
                System.out.print("Data content: ");
                for (byte b : bytes) {
                    System.out.printf("%02x ", b);
                }
                System.out.println();

                // 尝试将内容解释为字符串
                try {
                    String utf8String = new String(bytes, "UTF-8");
                    String asciiString = new String(bytes, "ASCII");
                    if (isPrintableString(utf8String)) {
                        System.out.println("Possible UTF-8 string: " + utf8String);
                    }
                    if (isPrintableString(asciiString) && !utf8String.equals(asciiString)) {
                        System.out.println("Possible ASCII string: " + asciiString);
                    }
                } catch (Exception e) {
                    // 忽略解码错误
                }
            }
        }, 0, -1, null); // 先hook所有内存范围
    }

    private boolean isPrintableString(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        // 检查字符串是否只包含可打印字符
        for (char c : str.toCharArray()) {
            if (c < 32 || c > 126) {
                return false;
            }
        }
        return true;
    }

    public void decryptStrings(String soPath) throws IOException {
        // 加载目标SO文件
        DalvikModule dm = vm.loadLibrary(new File(soPath), true); // 第二个参数true表示执行init_array

        targetModule = dm.getModule();

        // 打印所有记录的内存写入中可能的字符串
        System.out.println("\n开始分析内存写入的字符串内容:");
        Map<Long, byte[]> filteredMap = new HashMap<>();
        // 先过滤出在targetModule范围内的内存写入
        for (Map.Entry<Long, byte[]> entry : modifyMap.entrySet()) {
            long address = entry.getKey();
            if (targetModule != null) {
                for (MemRegion region : targetModule.getRegions()) {
                    if (address >= region.begin && address < region.end) {
                        filteredMap.put(address, entry.getValue());
                        break;
                    }
                }
            }
        }

        // 遍历过滤后的内存写入记录
        List<Map.Entry<Long, byte[]>> sortedEntries = new ArrayList<>(filteredMap.entrySet());
        sortedEntries.sort(Map.Entry.comparingByKey()); // 按地址排序

        // 用于存储合并后的内存块
        mergedMap.clear(); // 清空之前的数据
        long currentStartAddr = -1;
        ByteArrayOutputStream currentBytes = null;

        for (int i = 0; i < sortedEntries.size(); i++) {
            Map.Entry<Long, byte[]> entry = sortedEntries.get(i);
            long address = entry.getKey();
            byte[] bytes = entry.getValue();

            if (currentStartAddr == -1) {
                // 开始新的内存块
                currentStartAddr = address;
                currentBytes = new ByteArrayOutputStream();
                currentBytes.write(bytes);
            } else if (address == currentStartAddr + currentBytes.size()) {
                // 地址连续，合并内存块
                currentBytes.write(bytes);
            } else {
                // 地址不连续，保存当前内存块并开始新的内存块
                mergedMap.put(currentStartAddr, currentBytes.toByteArray());
                currentStartAddr = address;
                currentBytes = new ByteArrayOutputStream();
                currentBytes.write(bytes);
            }

            // 处理最后一个内存块
            if (i == sortedEntries.size() - 1 && currentBytes != null) {
                mergedMap.put(currentStartAddr, currentBytes.toByteArray());
            }
        }

        // 遍历合并后的内存块
        for (Map.Entry<Long, byte[]> entry : mergedMap.entrySet()) {
            long address = entry.getKey();
            byte[] bytes = entry.getValue();

            // 查找地址所属的段
            int segmentIndex = -1;
            MemRegion foundRegion = null;
            if (targetModule != null) {
                List<MemRegion> regions = targetModule.getRegions();
                for (int i = 0; i < regions.size(); i++) {
                    MemRegion region = regions.get(i);
                    if (address >= region.begin && address < region.end) {
                        segmentIndex = i;
                        foundRegion = region;
                        break;
                    }
                }
            }

            try {
                // 处理C风格字符串（以null结尾）
                int strLength = bytes.length;
                for (int i = 0; i < bytes.length; i++) {
                    if (bytes[i] == 0) {
                        strLength = i;
                        break;
                    }
                }
                byte[] strBytes = new byte[strLength];
                System.arraycopy(bytes, 0, strBytes, 0, strLength);

                String utf8String = new String(strBytes, "UTF-8");
                String asciiString = new String(strBytes, "ASCII");

                System.out.printf("\n内存地址: 0x%x", address);
                if (foundRegion != null) {
                    // 计算文件偏移，需要考虑加载基址和段映射
                    long fileOffset = foundRegion.offset + (address - foundRegion.begin);
                    // 检查偏移量是否有效
                    if (fileOffset >= 0) {
                        System.out.printf(" (段索引: %d, 段范围: 0x%x-0x%x, 权限: %d, 文件偏移: 0x%x)\n",
                                segmentIndex, foundRegion.begin, foundRegion.end, foundRegion.perms, fileOffset);
                    } else {
                        System.out.println(" (无效的文件偏移)");
                    }
                } else {
                    System.out.println(" (不在任何已知段内)");
                }

                System.out.print("数据内容: ");
                for (byte b : bytes) {
                    System.out.printf("%02x ", b);
                }
                System.out.println();

                if (isPrintableString(utf8String)) {
                    System.out.println("UTF-8字符串: " + utf8String);
                }
                if (isPrintableString(asciiString) && !utf8String.equals(asciiString)) {
                    System.out.println("ASCII字符串: " + asciiString);
                }
            } catch (Exception e) {
                // 忽略解码错误
            }
        }

        // 将修改写入新文件
        savePatchedSo(soPath);
    }

    private byte[] longToBytes(long value, int size) {
        ByteBuffer buffer = ByteBuffer.allocate(size)
                .order(ByteOrder.LITTLE_ENDIAN);
        switch (size) {
            case 1: buffer.put((byte) value); break;
            case 2: buffer.putShort((short) value); break;
            case 4: buffer.putInt((int) value); break;
            case 8: buffer.putLong(value); break;
        }
        return buffer.array();
    }

    private void savePatchedSo(String inputPath) throws IOException {
        // 获取输入文件的目录和文件名
        File inputFile = new File(inputPath);
        String outputFileName = inputFile.getName() + ".destr.so";
        String outputFilePath = new File(inputFile.getParentFile(), outputFileName).getPath();

        // 读取原始SO文件
        byte[] original = java.nio.file.Files.readAllBytes(inputFile.toPath());

        // 应用内存修改，使用合并后的内存块
        for (Map.Entry<Long, byte[]> entry : mergedMap.entrySet()) {
            System.out.printf("==========================\n");
            long memAddress = entry.getKey();
            System.out.printf("memAddress: 0x%x\n", memAddress);

            // 计算文件偏移时需要考虑段映射关系
            long fileOffset = memAddress - targetModule.base - 0x1000;

            System.out.printf("fileOffset: 0x%x\n", fileOffset);
            System.out.printf("original.length: 0x%x\n", original.length);

            if (fileOffset >= 0 && fileOffset < original.length) {
                System.out.print("\nfileOffset >= 0 && fileOffset < original.length\n");

                byte[] patch = entry.getValue();
                // 确保不会越界
                int patchLength = Math.min(patch.length, original.length - (int)fileOffset);

                // 打印原始内容
                byte[] originalBytes = new byte[patchLength];
                System.arraycopy(original, (int)fileOffset, originalBytes, 0, patchLength);
                System.out.printf("\n原始内容: 内存地址=0x%x, 文件偏移=0x%x\n", memAddress, fileOffset);
                System.out.print("原始数据: ");
                for (int i = 0; i < patchLength; i++) {
                    System.out.printf("%02x ", originalBytes[i]);
                }
                System.out.println();

                // 尝试将原始内容解释为字符串
                try {
                    String utf8String = new String(originalBytes, "UTF-8");
                    String asciiString = new String(originalBytes, "ASCII");
                    if (isPrintableString(utf8String)) {
                        System.out.println("原始UTF-8字符串: " + utf8String);
                    }
                    if (isPrintableString(asciiString) && !utf8String.equals(asciiString)) {
                        System.out.println("原始ASCII字符串: " + asciiString);
                    }
                } catch (Exception e) {
                    // 忽略解码错误
                }

                // 打印修改信息
                System.out.printf("\n应用修改: 内存地址=0x%x, 文件偏移=0x%x\n", memAddress, fileOffset);
                System.out.print("修改内容: ");
                for (int i = 0; i < patchLength; i++) {
                    System.out.printf("%02x ", patch[i]);
                }
                System.out.println();

                // 尝试将内容解释为字符串
                try {
                    byte[] strBytes = new byte[patchLength];
                    System.arraycopy(patch, 0, strBytes, 0, patchLength);
                    String utf8String = new String(strBytes, "UTF-8");
                    String asciiString = new String(strBytes, "ASCII");
                    if (isPrintableString(utf8String)) {
                        System.out.println("UTF-8字符串: " + utf8String);
                    }
                    if (isPrintableString(asciiString) && !utf8String.equals(asciiString)) {
                        System.out.println("ASCII字符串: " + asciiString);
                    }
                } catch (Exception e) {
                    // 忽略解码错误
                }

                System.arraycopy(patch, 0, original, (int)fileOffset, patchLength);
            }
        }

        // 写入新文件
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(original);
        }
        System.out.println("解密完成，保存至: " + outputFilePath);
    }

    public static void main(String[] args) {
        try {
            StringDecryptor decryptor = new StringDecryptor();
           decryptor.decryptStrings("unidbg-android/src/test/resources/example_binaries/ollvm_str/libnative-lib.so");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
