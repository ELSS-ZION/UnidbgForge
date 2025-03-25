# UnidbgForge

这是一个基于[unidbg](https://github.com/zhkl0228/unidbg)的工具集合，主要用于Android应用分析和逆向工程。

## 项目结构

- `unidbg-android/src/test/java/forge/` - 原创工具实现目录
  - `ollvm/` - OLLVM相关工具
    - `StringDecryptor.java` - OLLVM字符串解密工具

其他目录均为unidbg原有代码。

## 已实现功能

### OLLVM字符串解密

`StringDecryptor`工具可以通过unidbg模拟执行SO文件，自动捕获并记录内存写入操作，用于还原OLLVM字符串加密保护。主要特性：

- 自动跟踪内存写入操作
- 智能识别UTF-8/ASCII字符串
- 支持导出解密后的SO文件
