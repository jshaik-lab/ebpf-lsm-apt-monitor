# Action Plan: Paper 1 (Kernel Security)
## Path: /Users/jshaik/projects/EB1A/IEEETechnicalPapers/Paper1_ZeroTrustAgent

### 1. Technical Objective
Implement an eBPF-based monitor that feeds system call sequences (execve, connect, openat) into a local LLM to identify 'Intent-based' anomalies.

### 2. Required AI Code Components
- **BPF Program**: C code to hook syscalls and push data to a perf_buffer.
- **Python Wrapper**: BCC-based script to read the buffer.
- **Inference Engine**: Integration with a quantized model (e.g., Llama-3-8B-GGUF) to classify call sequences.

### 3. Dataset
- DARPA Transparent Computing traces or synthetic 'Syzbot' crash logs.