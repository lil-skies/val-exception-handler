# val-exception-handler

Attempted conversion of [tarekwiz / League-Unpacker (https://github.com/tarekwiz/League-Unpacker/blob/master/Unpackman/Main.cpp)] using RtlpCallVectoredHandlers instead of NtRaiseException

It's current state is rather underwhelming, as it is only able to properly dump the necessary UWORLD_STATE & UWORLD_KEY offsets

To update to current Windows version: 

```
const auto ki_dispatcher = reinterpret_cast<std::uintptr_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserExceptionDispatcher"));
const auto exception_dispatch = calculate_relative<std::int32_t>(ki_dispatcher + 0x29, 5, 1); //ki_dispatcher + ??? [new offset]
const auto rtlp = calculate_relative<std::int32_t>(exception_dispatch + 0x66, 5, 1); //exception_dispatch + ??? [new_offset]
```

