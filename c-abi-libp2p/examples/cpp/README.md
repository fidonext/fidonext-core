## Build
```
mkdir build
cd build
cmake ..
cmake --build .
```

# Use
1. Copy .dll or .so into folder near executable
2. Run through cmd/terminal
3. `ping --use-quic --lport 41001 --dport 41002 --duration 60`
4. `ping --use-quic --lport 41002 --dport 41001 --duration 60`