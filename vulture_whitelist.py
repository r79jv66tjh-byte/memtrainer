# Names that only code outside this project uses, so vulture cannot see the use.
# Kept by bin/dead-code-triage from AI-Coding-Tools; lines with another reason are kept as written.
_.dwSize  # ctypes structure field (debugger.py:281)
_.dwSize  # ctypes structure field (scanner_core.py:115)
_.dwSize  # ctypes structure field (scanner_core.py:245)
_.noise  # ctypes structure field (tests/target.py:30)
_.detail  # capstone.Cs option, read by capstone (debugger.py, remote.py, tests/test_core.py)
_._healed  # read through self.__dict__.get in Unity.main_hook (unity.py)
_._hook  # read through self.__dict__.get/pop in Unity.main_hook and close_hook (unity.py)
