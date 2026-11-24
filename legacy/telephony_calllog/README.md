# Legacy telephony call-log analysis

This is the preserved, independent telephone-call CSV analysis module. It is
not part of PS1 and is not included in the root project's active build or test
suite. The official PS1 implementation is the FunctionLog function-execution
library in the root project.

The original API documentation, data, examples, reports, Python analyzers, and
tests are retained here. The optional combined call-log/network investigator
also remains legacy because PS2 now has its own network-only evidence pipeline.

To build and test this module separately:

```powershell
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Run its Python tests from this directory with:

```powershell
python -m unittest discover -s tests\python -p "test_*.py" -v
```
