
/* CR0 flags */
CR0_PE = 0x1
CR0_MP = 0x2
CR0_EM = 0x4
CR0_TS = 0x8
CR0_ET = 0x10
CR0_NE = 0x20
CR0_WP = 0x10000
CR0_AM = 0x40000
CR0_NW = 0x20000000
CR0_CD = 0x40000000
CR0_PG = 0x80000000

/* CR4 flags */
CR4_VME = 0x1
CR4_PVI = 0x2
CR4_TSD = 0x4
CR4_DE = 0x8
CR4_PSE = 0x10
CR4_PAE = 0x20
CR4_MCE = 0x40
CR4_PGE = 0x80
CR4_FXSR = 0x200
CR4_XMMEXCPT = 0x400

/* Debug Registers */
DR6_LEGAL = 0xe00f
DR7_LEGAL = 0xffff0155
DR7_ACTIVE = 0x55
DR7_RESERVED_MASK = 0xdc00

/* EFLAGS */
EFLAGS_TF = 0x100
EFLAGS_INTERRUPT_MASK = 0x200
EFLAGS_V86_MASK = 0x20000
EFLAGS_ALIGN_CHECK = 0x40000
EFLAGS_VIF = 0x80000
EFLAGS_VIP = 0x100000
EFLAGS_USER_SANITIZE = 0x3f4dd7

/* KeFeatureBits flags */
KF_V86_VIS = 0x1
KF_RDTSC = 0x2
KF_CR4 = 0x4
KF_GLOBAL_PAGE = 0x10
KF_LARGE_PAGE = 0x20
KF_CMPXCHG8B = 0x80
KF_FAST_SYSCALL = 0x1000

/* KGDT selectors */
KGDT_NULL = 0x0
KGDT_R0_CODE = 0x8
KGDT_R0_DATA = 0x10
KGDT_R3_CODE = 0x18
KGDT_R3_DATA = 0x20
KGDT_TSS = 0x28
KGDT_R0_PCR = 0x30
KGDT_R3_TEB = 0x38
KGDT_VDM_TILE = 0x40
KGDT_LDT = 0x48
KGDT_DF_TSS = 0x50
KGDT_NMI_TSS = 0x58

/* Machine type definitions */
MACHINE_TYPE_ISA = 0x0
MACHINE_TYPE_EISA = 0x1
MACHINE_TYPE_MCA = 0x2

/* MSR definitions */
MSR_AMD_ACCESS = 0x9c5a203a
MSR_IA32_MISC_ENABLE = 0x1a0
MSR_EFER = 0xc0000080

/* MSR values */
MSR_NXE = 0x800
XHF_NOEXECUTE = 0x100000
MSR_XD_ENABLE_MASK = 0xfffffffb

/* WOW64 turbo dispatch system call types */
ServiceNoTurbo = 0x0
Service0Arg = 0x1
Service0ArgReloadState = 0x2
Service1ArgSp = 0x3
Service1ArgNSp = 0x4
Service2ArgNSpNSp = 0x5
Service2ArgNSpNSpReloadState = 0x6
Service2ArgSpNSp = 0x7
Service2ArgSpSp = 0x8
Service2ArgNSpSp = 0x9
Service3ArgNSpNSpNSp = 0xa
Service3ArgSpSpSp = 0xb
Service3ArgSpNSpNSp = 0xc
Service3ArgSpNSpNSpReloadState = 0xd
Service3ArgSpSpNSp = 0xe
Service3ArgNSpSpNSp = 0xf
Service3ArgSpNSpSp = 0x10
Service4ArgNSpNSpNSpNSp = 0x11
Service4ArgSpSpNSpNSp = 0x12
Service4ArgSpSpNSpNSpReloadState = 0x13
Service4ArgSpNSpNSpNSp = 0x14
Service4ArgSpNSpNSpNSpReloadState = 0x15
Service4ArgNSpSpNSpNSp = 0x16
Service4ArgSpSpSpNSp = 0x17
ServiceCpupTdQuerySystemTime = 0x18
ServiceCpupTdGetCurrentProcessorNumber = 0x19
ServiceCpupTdReadWriteFile = 0x1a
ServiceCpupTdDeviceIoControlFile = 0x1b
ServiceCpupTdRemoveIoCompletion = 0x1c
ServiceCpupTdWaitForMultipleObjects = 0x1d
ServiceCpupTdWaitForMultipleObjects32 = 0x1e
Wow64ServiceTypesCount = 0x1f

/* VDM constants */
VDM_INDEX_Invalid = 0x0
VDM_INDEX_0F = 0x1
VDM_INDEX_ESPrefix = 0x2
VDM_INDEX_CSPrefix = 0x3
VDM_INDEX_SSPrefix = 0x4
VDM_INDEX_DSPrefix = 0x5
VDM_INDEX_FSPrefix = 0x6
VDM_INDEX_GSPrefix = 0x7
VDM_INDEX_OPER32Prefix = 0x8
VDM_INDEX_ADDR32Prefix = 0x9
VDM_INDEX_INSB = 0xa
VDM_INDEX_INSW = 0xb
VDM_INDEX_OUTSB = 0xc
VDM_INDEX_OUTSW = 0xd
VDM_INDEX_PUSHF = 0xe
VDM_INDEX_POPF = 0xf
VDM_INDEX_INTnn = 0x10
VDM_INDEX_INTO = 0x11
VDM_INDEX_IRET = 0x12
VDM_INDEX_NPX = 0x13
VDM_INDEX_INBimm = 0x14
VDM_INDEX_INWimm = 0x15
VDM_INDEX_OUTBimm = 0x16
VDM_INDEX_OUTWimm = 0x17
VDM_INDEX_INB = 0x18
VDM_INDEX_INW = 0x19
VDM_INDEX_OUTB = 0x1a
VDM_INDEX_OUTW = 0x1b
VDM_INDEX_LOCKPrefix = 0x1c
VDM_INDEX_REPNEPrefix = 0x1d
VDM_INDEX_REPPrefix = 0x1e
VDM_INDEX_CLI = 0x1f
VDM_INDEX_STI = 0x20
VDM_INDEX_HLT = 0x21
MAX_VDM_INDEX = 0x22

/* XSAVE_AREA definitions */
XSTATE_MASK_LEGACY_FLOATING_POINT = 0x1
XSTATE_MASK_LEGACY_SSE = 0x2
XSTATE_MASK_LEGACY = 0x3
XSTATE_MASK_GSSE = 0x4

/* Miscellaneous constants */
KTIMER_TABLE_SIZE = 0x1100
FRAME_EDITED = 0xfff8
PF_XMMI_INSTRUCTIONS_AVAILABLE = 0x6
CPU_AMD = 0x2
CPU_INTEL = 0x1

/* ** FIELD OFFSETS *************** */

/* CONTEXT offsets */
CsContextFlags = 0x0
CsDr0 = 0x4
CsDr1 = 0x8
CsDr2 = 0xc
CsDr3 = 0x10
CsDr6 = 0x14
CsDr7 = 0x18
CsFloatSave = 0x1c
CsSegGs = 0x8c
CsSegFs = 0x90
CsSegEs = 0x94
CsSegDs = 0x98
CsEdi = 0x9c
CsEsi = 0xa0
CsEbx = 0xa4
CsEdx = 0xa8
CsEcx = 0xac
CsEax = 0xb0
CsEbp = 0xb4
CsEip = 0xb8
CsSegCs = 0xbc
CsEflags = 0xc0
CsEsp = 0xc4
CsSegSs = 0xc8
CsExtendedRegisters = 0xcc
ContextFrameLength = 0x2cc
CONTEXT_LENGTH = 0x2cc

/* KCALLOUT_FRAME offsets */
CuInStk = 0x0
CuTrFr = 0x4
CuCbStk = 0x8
CuEdi = 0xc
CuEsi = 0x10
CuEbx = 0x14
CuEbp = 0x18
CuRet = 0x1c
CuOutBf = 0x20
CuOutLn = 0x24

/* FLOATING_SAVE_AREA offsets */
FpControlWord = 0x0
FpStatusWord = 0x4
FpTagWord = 0x8
FpErrorOffset = 0xc
FpErrorSelector = 0x10
FpDataOffset = 0x14
FpDataSelector = 0x18
FpRegisterArea = 0x1c

/* XSAVE_FORMAT offsets */
FxControlWord = 0x0
FxStatusWord = 0x2
FxTagWord = 0x4
FxErrorOpcode = 0x6
FxErrorOffset = 0x8
FxErrorSelector = 0xc
FxDataOffset = 0x10
FxDataSelector = 0x14
FxMxCsr = 0x18
XSAVE_FORMAT_SIZE = 0x200

/* KGDTENTRY offsets */
KgdtLimitLow = 0x0
KgdtBaseLow = 0x2
KgdtHighWord = 0x4
KgdtBaseMid = 0x4
KgdtLimitHi = 0x6
KgdtBaseHi = 0x7

/* KPRCB offsets */
PbCurrentThread = 0x4
PbNextThread = 0x8
PbIdleThread = 0xc
PbCpuType = 0x18
PbCpuID = 0x19
PbCpuStep = 0x1a
PbProcessorState = 0x1c
PbParentNode = 0x54c
PbHalReserved = 0x37c
PbNumber = 0x10
PbLockQueue = 0x418
PbInterruptCount = 0x524
PbKernelTime = 0x528
PbUserTime = 0x52c
PbDpcTime = 0x530
PbInterruptTime = 0x538
PbAdjustDpcThreshold = 0x53c
PbPageColor = 0x540
PbDebuggerSavedIRQL = 0x545
PbNodeShiftedColor = 0x548
PbSecondaryColorMask = 0x558
PbSystemCalls = 0x598
PbPPLookasideList = 0x5e0
PbPPNPagedLookasideList = 0x660
PbPPPagedLookasideList = 0x760
PbPacketBarrier = 0x860
PbReverseStall = 0x864
PbIpiFrame = 0x868
PbCurrentPacket = 0x8a0
PbTargetSet = 0x8ac
PbWorkerRoutine = 0x8b0
PbIpiFrozen = 0x8b4
PbRequestSummary = 0x8e0
PbDpcStack = 0x948
PbMaximumDpcQueueDepth = 0x94c
PbDpcRequestRate = 0x950
PbMinimumDpcRate = 0x954
PbDpcLastCount = 0x960
PbPrcbLock = 0x95c
PbQuantumEnd = 0x981
PbDpcRoutineActive = 0x95a
PbIdleSchedule = 0x983
PbDeferredReadyListHead = 0xaf0
PbReadySummary = 0x9e8
PbWaitListHead = 0x9e0
PbDispatcherReadyListHead = 0x9f0
PbChainedInterruptList = 0xb20
ProcessorBlockLength = 0xec0

/* KPCR offsets */
PcExceptionList = 0x0
PcTssCopy = 0xc
PcContextSwitches = 0x10
PcSetMemberCopy = 0x14
PcTeb = 0x18
PcSelfPcr = 0x1c
PcPrcb = 0x20
PcIrql = 0x24
PcIRR = 0x28
PcIrrActive = 0x2c
PcIDR = 0x30
PcIdt = 0x38
PcGdt = 0x3c
PcTss = 0x40
PcSetMember = 0x48
PcStallScaleFactor = 0x4c
PcNumber = 0x51
PcVdmAlert = 0x54
PcHal = 0x94
PcPrcbData = 0x120
PcCurrentThread = 0x124
PcParentNode = 0x66c
PcInterruptCount = 0x644
ProcessorControlRegisterLength = 0xfe0

/* PEB offsets */
PebBeingDebugged = 0x2
PebKernelCallbackTable = 0x2c

/* KPROCESSOR_STATE offsets */
PsContextFrame = 0x0
PsSpecialRegisters = 0x2cc
ProcessorStateLength = 0x320

/* KSPECIAL_REGISTERS offsets */
SrCr0 = 0x0
SrCr2 = 0x4
SrCr3 = 0x8
SrCr4 = 0xc
SrKernelDr0 = 0x10
SrKernelDr1 = 0x14
SrKernelDr2 = 0x18
SrKernelDr3 = 0x1c
SrKernelDr6 = 0x20
SrKernelDr7 = 0x24
SrGdtr = 0x28
SrIdtr = 0x30
SrTr = 0x38
SrLdtr = 0x3a

/* KSYSTEM_TIME offsets */
StLowTime = 0x0
StHigh1Time = 0x4
StHigh2Time = 0x8

/* TEB offsets (duplicates Te* definitions!) */
TbExceptionList = 0x0
TbStackBase = 0x4
TbStackLimit = 0x8
TbVersion = 0x10
TbFiberData = 0x10
TbArbitraryUserPointer = 0x14
TbEnvironmentPointer = 0x1c
TbClientId = 0x20
TbThreadLocalStoragePointer = 0x2c
TbCountOfOwnedCriticalSections = 0x38
TbCsrClientThread = 0x3c
TbWOW32Reserved = 0xc0
TbSystemReserved1 = 0xcc
TbExceptionCode = 0x1a4
TbGdiThreadLocalInfo = 0x6c8
TbglDispatchTable = 0x7c4
TbglSectionInfo = 0xbe0
TbglSection = 0xbe4
TbglTable = 0xbe8
TbglCurrentRC = 0xbec
TbglContext = 0xbf0
TbDeallocationStack = 0xe0c
TbVdm = 0xf18
TbGdiBatchCount = 0xf70
TebPeb = 0x30

/* KTRAP_FRAME */
TsDbgEbp = 0x0
TsDbgEip = 0x4
TsDbgArgMark = 0x8
TsTempSegCs = 0x10
TsTempEsp = 0x14
TsDr0 = 0x18
TsDr1 = 0x1c
TsDr2 = 0x20
TsDr3 = 0x24
TsDr6 = 0x28
TsDr7 = 0x2c
TsSegGs = 0x30
TsSegEs = 0x34
TsSegDs = 0x38
TsEdx = 0x3c
TsEcx = 0x40
TsEax = 0x44
TsPreviousPreviousMode = 0x48
TsExceptionList = 0x4c
TsSegFs = 0x50
TsEdi = 0x54
TsEsi = 0x58
TsEbx = 0x5c
TsEbp = 0x60
TsErrCode = 0x64
TsEip = 0x68
TsSegCs = 0x6c
TsEflags = 0x70
TsHardwareEsp = 0x74
TsHardwareSegSs = 0x78
TsDbgArgPointer = 0xc
TsV86Es = 0x7c
TsV86Ds = 0x80
TsV86Fs = 0x84
TsV86Gs = 0x88
KTRAP_FRAME_LENGTH = 0x8c
KTRAP_FRAME_ALIGN = 0x4

/* KTSS offsets */
TssEsp0 = 0x4
TssCR3 = 0x1c
TssEip = 0x20
TssEFlags = 0x24
TssEax = 0x28
TssEbx = 0x34
TssEcx = 0x2c
TssEdx = 0x30
TssEsp = 0x38
TssEbp = 0x3c
TssEsi = 0x40
TssEdi = 0x44
TssEs = 0x48
TssCs = 0x4c
TssSs = 0x50
TssDs = 0x54
TssFs = 0x58
TssGs = 0x5c
TssLDT = 0x60
TssIoMapBase = 0x66
TssIoMaps = 0x68
TssLength = 0x20ac

/* XSTATE_CONFIGURATION offsets */
XcfgEnabledFeatures = 0x0

/* XSTATE_CONTEXT offsets */
XctxMask = 0x0
XctxLength = 0x8
XctxArea = 0x10

/* XSAVE_AREA offsets */
XsaHeader = 0x200
XsaHeaderLength = 0x40

/* Data access macros */
#define USERDATA ds:[HEX(0FFDF0000)]
#ifdef CONFIG_SMP
#define PCR fs:
#else
#define PCR ds:[HEX(0FFDFF000)]
#endif
NPX_STATE_NOT_LOADED = 0xa
NPX_STATE_LOADED = 0x0

/* KPCR */
KPCR_EXCEPTION_LIST = 0x0
KPCR_PERF_GLOBAL_GROUP_MASK = 0x8
KPCR_CONTEXT_SWITCHES = 0x10
KPCR_TEB = 0x18
KPCR_SELF = 0x1c
KPCR_PRCB = 0x20
KPCR_IDT = 0x38
KPCR_GDT = 0x3c
KPCR_TSS = 0x40
KPCR_STALL_SCALE_FACTOR = 0x4c
KPCR_PRCB_DATA = 0x120
KPCR_CURRENT_THREAD = 0x124
KPCR_PRCB_NEXT_THREAD = 0x128
KPCR_PRCB_DPC_QUEUE_DEPTH = 0xa4c
KPCR_PRCB_DPC_STACK = 0xa68
KPCR_PRCB_MAXIMUM_DPC_QUEUE_DEPTH = 0xa6c
KPCR_PRCB_DPC_ROUTINE_ACTIVE = 0xa7a
KPCR_PRCB_TIMER_REQUEST = 0xa88
KPCR_PRCB_QUANTUM_END = 0xaa1
KPCR_PRCB_DEFERRED_READY_LIST_HEAD = 0xc10
KPCR_PRCB_POWER_STATE_IDLE_FUNCTION = 0xec0

/* KTRAP_FRAME */
KTRAP_FRAME_DEBUGEBP = 0x0
KTRAP_FRAME_DEBUGEIP = 0x4
KTRAP_FRAME_TEMPESP = 0x14
KTRAP_FRAME_DR0 = 0x18
KTRAP_FRAME_DR1 = 0x1c
KTRAP_FRAME_DR2 = 0x20
KTRAP_FRAME_DR3 = 0x24
KTRAP_FRAME_DR6 = 0x28
KTRAP_FRAME_DR7 = 0x2c
KTRAP_FRAME_GS = 0x30
KTRAP_FRAME_ES = 0x34
KTRAP_FRAME_DS = 0x38
KTRAP_FRAME_EDX = 0x3c
KTRAP_FRAME_ECX = 0x40
KTRAP_FRAME_EAX = 0x44
KTRAP_FRAME_PREVIOUS_MODE = 0x48
KTRAP_FRAME_EXCEPTION_LIST = 0x4c
KTRAP_FRAME_FS = 0x50
KTRAP_FRAME_EDI = 0x54
KTRAP_FRAME_ESI = 0x58
KTRAP_FRAME_EBX = 0x5c
KTRAP_FRAME_EBP = 0x60
KTRAP_FRAME_ERROR_CODE = 0x64
KTRAP_FRAME_EIP = 0x68
KTRAP_FRAME_CS = 0x6c
KTRAP_FRAME_EFLAGS = 0x70
KTRAP_FRAME_ESP = 0x74
KTRAP_FRAME_SS = 0x78
KTRAP_FRAME_V86_ES = 0x7c
KTRAP_FRAME_V86_DS = 0x80
KTRAP_FRAME_V86_FS = 0x84
KTRAP_FRAME_V86_GS = 0x88
KTRAP_FRAME_SIZE = 0x8c

/* CONTEXT */
CONTEXT_FLAGS = 0x0
CONTEXT_SEGGS = 0x8c
CONTEXT_SEGFS = 0x90
CONTEXT_SEGES = 0x94
CONTEXT_SEGDS = 0x98
CONTEXT_EDI = 0x9c
CONTEXT_ESI = 0xa0
CONTEXT_EBX = 0xa4
CONTEXT_EDX = 0xa8
CONTEXT_ECX = 0xac
CONTEXT_EAX = 0xb0
CONTEXT_EBP = 0xb4
CONTEXT_EIP = 0xb8
CONTEXT_SEGCS = 0xbc
CONTEXT_EFLAGS = 0xc0
CONTEXT_ESP = 0xc4
CONTEXT_SEGSS = 0xc8
CONTEXT_FRAME_LENGTH = 0x2cc

/* FIBER */
FIBER_PARAMETER = 0x0
FIBER_EXCEPTION_LIST = 0x4
FIBER_STACK_BASE = 0x8
FIBER_STACK_LIMIT = 0xc
FIBER_DEALLOCATION_STACK = 0x10
FIBER_CONTEXT = 0x14
FIBER_CONTEXT_FLAGS = 0x14
FIBER_CONTEXT_EAX = 0xc4
FIBER_CONTEXT_EBX = 0xb8
FIBER_CONTEXT_ECX = 0xc0
FIBER_CONTEXT_EDX = 0xbc
FIBER_CONTEXT_ESI = 0xb4
FIBER_CONTEXT_EDI = 0xb0
FIBER_CONTEXT_EBP = 0xc8
FIBER_CONTEXT_EIP = 0xcc
FIBER_CONTEXT_ESP = 0xd8
FIBER_CONTEXT_DR6 = 0x28
FIBER_CONTEXT_FLOAT_SAVE_CONTROL_WORD = 0x30
FIBER_CONTEXT_FLOAT_SAVE_STATUS_WORD = 0x34
FIBER_CONTEXT_FLOAT_SAVE_TAG_WORD = 0x38
FIBER_GUARANTEED_STACK_BYTES = 0x2e0
FIBER_FLS_DATA = 0x2e4
FIBER_ACTIVATION_CONTEXT_STACK = 0x2e8

/* KTSS */
KTSS_IOMAPBASE = 0x66
KTSS_ESP0 = 0x4

/* EXCEPTION_RECORD */
EXCEPTION_RECORD_EXCEPTION_CODE = 0x0
EXCEPTION_RECORD_EXCEPTION_FLAGS = 0x4
EXCEPTION_RECORD_EXCEPTION_RECORD = 0x8
EXCEPTION_RECORD_EXCEPTION_ADDRESS = 0xc
EXCEPTION_RECORD_NUMBER_PARAMETERS = 0x10
EXCEPTION_RECORD_EXCEPTION_ADDRESS = 0xc
SIZEOF_EXCEPTION_RECORD = 0x50
EXCEPTION_RECORD_LENGTH = 0x50

/* EXCEPTION_POINTERS */
EXCEPTION_POINTERS_EXCEPTION_RECORD = 0x0
EXCEPTION_POINTERS_CONTEXT_RECORD = 0x4
SIZEOF_EXCEPTION_POINTERS = 0x8

/* KTHREAD */
KTHREAD_DEBUG_ACTIVE = 0x3
KTHREAD_INITIAL_STACK = 0x18
KTHREAD_STACK_LIMIT = 0x1c
KTHREAD_TEB = 0x74
KTHREAD_KERNEL_STACK = 0x20
KTHREAD_APCSTATE_PROCESS = 0x38
KTHREAD_PENDING_KERNEL_APC = 0x3d
KTHREAD_CONTEXT_SWITCHES = 0x48
KTHREAD_STATE_ = 0x4c
KTHREAD_NPX_STATE = 0x4d
KTHREAD_WAIT_IRQL = 0x4e
KTHREAD_WAIT_REASON = 0x5a
KTHREAD_COMBINED_APC_DISABLE = 0x70
KTHREAD_SPECIAL_APC_DISABLE = 0x72
KTHREAD_LARGE_STACK = 0x107
KTHREAD_TRAP_FRAME = 0x110
KTHREAD_CALLBACK_STACK = 0x114
KTHREAD_APC_STATE_INDEX = 0x11c
KTHREAD_STACK_BASE = 0x158

/* KPROCESS */
KPROCESS_DIRECTORY_TABLE_BASE = 0x18
KPROCESS_LDT_DESCRIPTOR0 = 0x20
KPROCESS_LDT_DESCRIPTOR1 = 0x24
KPROCESS_INT21_DESCRIPTOR0 = 0x28
KPROCESS_INT21_DESCRIPTOR1 = 0x2c
KPROCESS_IOPM_OFFSET = 0x30

/* TEB */
TEB_EXCEPTION_LIST = 0x0
TEB_STACK_BASE = 0x4
TEB_STACK_LIMIT = 0x8
TEB_FIBER_DATA = 0x10
TEB_SELF = 0x18
TEB_PEB = 0x30
TEB_EXCEPTION_CODE = 0x1a4
TEB_ACTIVATION_CONTEXT_STACK_POINTER = 0x1a8
TEB_GL_TABLE = 0xbe8
TEB_DEALLOCATION_STACK = 0xe0c
TEB_GDI_BATCH_COUNT = 0xf70
TEB_GUARANTEED_STACK_BYTES = 0xf78
TEB_FLS_DATA = 0xfb4

/* PEB */
PEB_KERNEL_CALLBACK_TABLE = 0x2c

/* Misc */
NPX_FRAME_LENGTH = 0x210
FN_CR0_NPX_STATE = 0x20c
FP_CONTROL_WORD = 0x0
FP_STATUS_WORD = 0x4
FP_TAG_WORD = 0x8
FP_DATA_SELECTOR = 0x18
CBSTACK_RESULT = 0x20
CBSTACK_RESULT_LENGTH = 0x24
CBSTACK_TRAP_FRAME = 0x4
CBSTACK_CALLBACK_STACK = 0x8
SIZEOF_FX_SAVE_AREA = 0x210
KUSER_SHARED_SYSCALL = 0x7ffe0300
EXCEPTION_EXECUTE_HANDLER = 0x1
STATUS_CALLBACK_POP_STACK = 0xc0000423
CONTEXT_ALIGNED_SIZE = 0x2cc
PROCESSOR_FEATURE_FXSR = 0x7ffe0278
KUSER_SHARED_SYSCALL_RET = 0x7ffe0304
USER_SHARED_DATA = 0x7ffe0000
USER_SHARED_DATA_PROCESSOR_FEATURES = 0x274

/* Pointer size */
SizeofPointer = 0x4

/* Bug Check Codes */
APC_INDEX_MISMATCH = 0x1
INVALID_AFFINITY_SET = 0x3
INVALID_DATA_ACCESS_TRAP = 0x4
IRQL_NOT_GREATER_OR_EQUAL = 0x9
IRQL_NOT_LESS_OR_EQUAL = 0xa
NO_USER_MODE_CONTEXT = 0xe
SPIN_LOCK_ALREADY_OWNED = 0xf
SPIN_LOCK_NOT_OWNED = 0x10
THREAD_NOT_MUTEX_OWNER = 0x11
TRAP_CAUSE_UNKNOWN = 0x12
KMODE_EXCEPTION_NOT_HANDLED = 0x1e
KERNEL_APC_PENDING_DURING_EXIT = 0x20
PANIC_STACK_SWITCH = 0x2b
DATA_BUS_ERROR = 0x2e
INSTRUCTION_BUS_ERROR = 0x2f
SYSTEM_EXIT_OWNED_MUTEX = 0x39
PAGE_FAULT_WITH_INTERRUPTS_OFF = 0x49
IRQL_GT_ZERO_AT_SYSTEM_SERVICE = 0x4a
DATA_COHERENCY_EXCEPTION = 0x55
INSTRUCTION_COHERENCY_EXCEPTION = 0x56
HAL1_INITIALIZATION_FAILED = 0x61
UNEXPECTED_KERNEL_MODE_TRAP = 0x7f
NMI_HARDWARE_FAILURE = 0x80
SPIN_LOCK_INIT_FAILURE = 0x81
ATTEMPTED_SWITCH_FROM_DPC = 0xb8
KERNEL_SECURITY_CHECK_FAILURE = 0x139

/* Breakpoints */
BREAKPOINT_BREAK = 0x0
BREAKPOINT_PRINT = 0x1
BREAKPOINT_PROMPT = 0x2
BREAKPOINT_LOAD_SYMBOLS = 0x3
BREAKPOINT_UNLOAD_SYMBOLS = 0x4
BREAKPOINT_COMMAND_STRING = 0x5

/* Context Frame Flags */
CONTEXT_FULL = 0x10007
CONTEXT_CONTROL = 0x10001
CONTEXT_INTEGER = 0x10002
CONTEXT_FLOATING_POINT = 0x10008
CONTEXT_DEBUG_REGISTERS = 0x10010
CONTEXT_SEGMENTS = 0x10004

/* Exception flags */
EXCEPTION_NONCONTINUABLE = 0x1
EXCEPTION_UNWINDING = 0x2
EXCEPTION_EXIT_UNWIND = 0x4
EXCEPTION_STACK_INVALID = 0x8
EXCEPTION_NESTED_CALL = 0x10
EXCEPTION_TARGET_UNWIND = 0x20
EXCEPTION_COLLIDED_UNWIND = 0x40
EXCEPTION_UNWIND = 0x66
EXCEPTION_EXECUTE_HANDLER = 0x1
EXCEPTION_CONTINUE_SEARCH = 0x0
EXCEPTION_CONTINUE_EXECUTION = 0xffffffff
EXCEPTION_CHAIN_END = 0xffffffff

/* Exception types */
ExceptionContinueExecution = 0x0
ExceptionContinueSearch = 0x1
ExceptionNestedException = 0x2
ExceptionCollidedUnwind = 0x3

/* Fast Fail Constants */
FAST_FAIL_GUARD_ICALL_CHECK_FAILURE = 0xa

/* Interrupt object types */
InLevelSensitive = 0x0
InLatched = 0x1

/* IPI */
IPI_APC = 0x1
IPI_DPC = 0x2
IPI_FREEZE = 0x4
IPI_PACKET_READY = 0x8
IPI_SYNCH_REQUEST = 0x10

/* IRQL */
PASSIVE_LEVEL = 0x0
APC_LEVEL = 0x1
DISPATCH_LEVEL = 0x2
CLOCK1_LEVEL = 0x1c
CLOCK2_LEVEL = 0x1c
IPI_LEVEL = 0x1d
POWER_LEVEL = 0x1e
PROFILE_LEVEL = 0x1b
HIGH_LEVEL = 0x1f
#ifndef CONFIG_SMP
SYNCH_LEVEL = 0x2
#else
SYNCH_LEVEL = 0x1b
#endif

/* Lock Queue */
LOCK_QUEUE_WAIT = 0x1
LOCK_QUEUE_OWNER = 0x2
LockQueueDispatcherLock = 0x0

/* Process states */
ProcessInMemory = 0x0
ProcessOutOfMemory = 0x1
ProcessInTransition = 0x2

/* Processor mode */
KernelMode = 0x0
UserMode = 0x1

/* Service Table Constants */
NUMBER_SERVICE_TABLES = 0x2
SERVICE_NUMBER_MASK = 0xfff
SERVICE_TABLE_SHIFT = 0x8
SERVICE_TABLE_MASK = 0x10
SERVICE_TABLE_TEST = 0x10

/* Status codes */
STATUS_ACCESS_VIOLATION = 0xc0000005
STATUS_ASSERTION_FAILURE = 0xc0000420
STATUS_ARRAY_BOUNDS_EXCEEDED = 0xc000008c
STATUS_BAD_COMPRESSION_BUFFER = 0xc0000242
STATUS_BREAKPOINT = 0x80000003
STATUS_CALLBACK_POP_STACK = 0xc0000423
STATUS_DATATYPE_MISALIGNMENT = 0x80000002
STATUS_FLOAT_DENORMAL_OPERAND = 0xc000008d
STATUS_FLOAT_DIVIDE_BY_ZERO = 0xc000008e
STATUS_FLOAT_INEXACT_RESULT = 0xc000008f
STATUS_FLOAT_INVALID_OPERATION = 0xc0000090
STATUS_FLOAT_OVERFLOW = 0xc0000091
STATUS_FLOAT_STACK_CHECK = 0xc0000092
STATUS_FLOAT_UNDERFLOW = 0xc0000093
STATUS_FLOAT_MULTIPLE_FAULTS = 0xc00002b4
STATUS_FLOAT_MULTIPLE_TRAPS = 0xc00002b5
STATUS_GUARD_PAGE_VIOLATION = 0x80000001
STATUS_ILLEGAL_FLOAT_CONTEXT = 0xc000014a
STATUS_ILLEGAL_INSTRUCTION = 0xc000001d
STATUS_INSTRUCTION_MISALIGNMENT = 0xc00000aa
STATUS_INVALID_HANDLE = 0xc0000008
STATUS_INVALID_LOCK_SEQUENCE = 0xc000001e
STATUS_INVALID_OWNER = 0xc000005a
STATUS_INVALID_PARAMETER = 0xc000000d
STATUS_INVALID_PARAMETER_1 = 0xc00000ef
STATUS_INVALID_SYSTEM_SERVICE = 0xc000001c
STATUS_INTEGER_DIVIDE_BY_ZERO = 0xc0000094
STATUS_INTEGER_OVERFLOW = 0xc0000095
STATUS_IN_PAGE_ERROR = 0xc0000006
STATUS_KERNEL_APC = 0x100
STATUS_LONGJUMP = 0x80000026
STATUS_NO_CALLBACK_ACTIVE = 0xc0000258
STATUS_NO_EVENT_PAIR = 0xc000014e
STATUS_PRIVILEGED_INSTRUCTION = 0xc0000096
STATUS_SINGLE_STEP = 0x80000004
STATUS_STACK_BUFFER_OVERRUN = 0xc0000409
STATUS_STACK_OVERFLOW = 0xc00000fd
STATUS_SUCCESS = 0x0
STATUS_THREAD_IS_TERMINATING = 0xc000004b
STATUS_TIMEOUT = 0x102
STATUS_UNWIND = 0xc0000027
STATUS_UNWIND_CONSOLIDATE = 0x80000029
STATUS_USER_APC = 0xc0
STATUS_WAKE_SYSTEM = 0x40000294
STATUS_WAKE_SYSTEM_DEBUGGER = 0x80000007

/* TLS defines */
TLS_MINIMUM_AVAILABLE = 0x40
TLS_EXPANSION_SLOTS = 0x400

/* Thread states */
Initialized = 0x0
Ready = 0x1
Running = 0x2
Standby = 0x3
Terminated = 0x4
Waiting = 0x5

/* Wait type / reason */
WrExecutive = 0x7
WrMutex = 0x1d
WrDispatchInt = 0x1f
WrQuantumEnd = 0x1e
WrEventPair = 0xe
WaitAny = 0x1
WaitAll = 0x0

/* Stack sizes */
KERNEL_STACK_SIZE = 0x3000
KERNEL_LARGE_STACK_SIZE = 0xf000
KERNEL_LARGE_STACK_COMMIT = 0x3000
DOUBLE_FAULT_STACK_SIZE = 0x3000

/* Miscellaneous Definitions */
TRUE = 0x1
FALSE = 0x0
PAGE_SIZE = 0x1000
Executive = 0x0
LOW_REALTIME_PRIORITY = 0x10
CLOCK_QUANTUM_DECREMENT = 0x3
WAIT_QUANTUM_DECREMENT = 0x1
MAXIMUM_PROCESSORS = 0x20
INITIAL_STALL_COUNT = 0x64
KI_EXCEPTION_ACCESS_VIOLATION = 0x10000004
DBG_STATUS_CONTROL_C = 0x1
MAXIMUM_IDTVECTOR = 0xff
PRIMARY_VECTOR_BASE = 0x30
RPL_MASK = 0x3
MODE_MASK = 0x1

/* KAPC */
ApType = 0x0
ApSize = 0x2
ApThread = 0x8
ApApcListEntry = 0xc
ApKernelRoutine = 0x14
ApRundownRoutine = 0x18
ApNormalRoutine = 0x1c
ApNormalContext = 0x20
ApSystemArgument1 = 0x24
ApSystemArgument2 = 0x28
ApApcStateIndex = 0x2c
ApApcMode = 0x2d
ApInserted = 0x2e
ApcObjectLength = 0x30

/* KAPC offsets (relative to NormalRoutine) */
ArNormalRoutine = 0x0
ArNormalContext = 0x4
ArSystemArgument1 = 0x8
ArSystemArgument2 = 0xc
ApcRecordLength = 0x10

/* KAPC_STATE */
AsApcListHead = 0x0
AsProcess = 0x10
AsKernelApcInProgress = 0x14
AsKernelApcPending = 0x15
AsUserApcPending = 0x16

/* CLIENT_ID */
CidUniqueProcess = 0x0
CidUniqueThread = 0x4

/* RTL_CRITICAL_SECTION */
CsDebugInfo = 0x0
CsLockCount = 0x4
CsRecursionCount = 0x8
CsOwningThread = 0xc
CsLockSemaphore = 0x10
CsSpinCount = 0x14

/* RTL_CRITICAL_SECTION_DEBUG */
CsType = 0x0
CsCreatorBackTraceIndex = 0x2
CsCriticalSection = 0x4
CsProcessLocksList = 0x8
CsEntryCount = 0x10
CsContentionCount = 0x14

/* KDEVICE_QUEUE_ENTRY */
DeDeviceListEntry = 0x0
DeSortKey = 0x8
DeInserted = 0xc
DeviceQueueEntryLength = 0x10

/* KDPC */
DpType = 0x0
DpImportance = 0x1
DpNumber = 0x2
DpDpcListEntry = 0x4
DpDeferredRoutine = 0xc
DpDeferredContext = 0x10
DpSystemArgument1 = 0x14
DpSystemArgument2 = 0x18
DpDpcData = 0x1c
DpcObjectLength = 0x20

/* KDEVICE_QUEUE */
DvType = 0x0
DvSize = 0x2
DvDeviceListHead = 0x4
DvSpinLock = 0xc
DvBusy = 0x10
DeviceQueueObjectLength = 0x14

/* EXCEPTION_RECORD */
ErExceptionCode = 0x0
ErExceptionFlags = 0x4
ErExceptionRecord = 0x8
ErExceptionAddress = 0xc
ErNumberParameters = 0x10
ErExceptionInformation = 0x14
ExceptionRecordLength = 0x50
EXCEPTION_RECORD_LENGTH = 0x50

/* EPROCESS */
EpDebugPort = 0xcc
EpVdmObjects = 0x144
ExecutiveProcessObjectLength = 0x278

/* ETHREAD offsets */
EtCid = 0x1e4
ExecutiveThreadObjectLength = 0x250

/* KEVENT */
EvType = 0x0
EvSize = 0x2
EvSignalState = 0x4
EvWaitListHead = 0x8
EventObjectLength = 0x10

/* FIBER */
FbFiberData = 0x0
FbExceptionList = 0x4
FbStackBase = 0x8
FbStackLimit = 0xc
FbDeallocationStack = 0x10
FbFiberContext = 0x14
FbFlsData = 0x2e4
FbGuaranteedStackBytes = 0x2e0

/* FAST_MUTEX */
FmCount = 0x0
FmOwner = 0x4
FmContention = 0x8
FmOldIrql = 0x1c

/* GETSETCONTEXT offsets */
GetSetCtxContextPtr = 0x44

/* KINTERRUPT */
InType = 0x0
InSize = 0x2
InInterruptListEntry = 0x4
InServiceRoutine = 0xc
InServiceContext = 0x10
InSpinLock = 0x14
InTickCount = 0x18
InActualLock = 0x1c
InDispatchAddress = 0x20
InVector = 0x24
InIrql = 0x28
InSynchronizeIrql = 0x29
InFloatingSave = 0x2a
InConnected = 0x2b
InNumber = 0x2c
InShareVector = 0x2d
InMode = 0x30
InServiceCount = 0x34
InDispatchCount = 0x38
InDispatchCode = 0x3c
InterruptObjectLength = 0x1e4

/* KSPIN_LOCK_QUEUE */
LqNext = 0x0
LqLock = 0x4
LOCK_QUEUE_HEADER_SIZE = 0x8

/* KLOCK_QUEUE_HANDLE */
LqhLockQueue = 0x0
LqhNext = 0x0
LqhLock = 0x4
LqhOldIrql = 0x8

/* LARGE_INTEGER */
LiLowPart = 0x0
LiHighPart = 0x4

/* LOADER_PARAMETER_BLOCK (rel. to LoadOrderListHead) */
LpbKernelStack = 0x18
LpbPrcb = 0x1c
LpbProcess = 0x20
LpbThread = 0x24

/* LIST_ENTRY */
LsFlink = 0x0
LsBlink = 0x4

/* PEB */
PeBeingDebugged = 0x2
PeProcessParameters = 0x10
PeKernelCallbackTable = 0x2c
ProcessEnvironmentBlockLength = 0x230

/* KPROFILE */
PfType = 0x0
PfSize = 0x2
PfProfileListEntry = 0x4
PfProcess = 0xc
PfRangeBase = 0x10
PfRangeLimit = 0x14
PfBucketShift = 0x18
PfBuffer = 0x1c
PfSegment = 0x20
PfAffinity = 0x24
PfSource = 0x28
PfStarted = 0x2c
ProfileObjectLength = 0x30

/* PORT_MESSAGE */
PmLength = 0x0
PmZeroInit = 0x4
PmClientId = 0x8
PmProcess = 0x8
PmThread = 0xc
PmMessageId = 0x10
PmClientViewSize = 0x14
PortMessageLength = 0x18

/* KPROCESS */
PrType = 0x0
PrSize = 0x2
PrSignalState = 0x4
PrProfileListHead = 0x10
PrDirectoryTableBase = 0x18
PrLdtDescriptor = 0x20
PrInt21Descriptor = 0x28
PrThreadListHead = 0x50
PrAffinity = 0x5c
PrReadyListHead = 0x40
PrSwapListEntry = 0x48
PrActiveProcessors = 0x34
PrProcessFlags = 0x60
PrBasePriority = 0x64
PrQuantumReset = 0x65
PrIopmOffset = 0x30
PrKernelTime = 0x38
PrUserTime = 0x3c
PrVdmTrapcHandler = 0x4c
PrFlags = 0x6b
KernelProcessObjectLength = 0x78

/* KQUEUE */
QuType = 0x0
QuSize = 0x2
QuSignalState = 0x4
QuEntryListHead = 0x10
QuCurrentCount = 0x18
QuMaximumCount = 0x1c
QuThreadListHead = 0x20
QueueObjectLength = 0x28

/* KSERVICE_TABLE_DESCRIPTOR offsets */
SdBase = 0x0
SdCount = 0x4
SdLimit = 0x8
SdNumber = 0xc
SdLength = 0x10

/* STRING */
StrLength = 0x0
StrMaximumLength = 0x2
StrBuffer = 0x4

/* TEB */
TeExceptionList = 0x0
TeStackBase = 0x4
TeStackLimit = 0x8
TeFiberData = 0x10
TeSelf = 0x18
TeEnvironmentPointer = 0x1c
TeClientId = 0x20
TeActiveRpcHandle = 0x28
TeThreadLocalStoragePointer = 0x2c
TePeb = 0x30
TeLastErrorValue = 0x34
TeCountOfOwnedCriticalSections = 0x38
TeCsrClientThread = 0x3c
TeWOW32Reserved = 0xc0
TeExceptionCode = 0x1a4
TeActivationContextStackPointer = 0x1a8
TeGdiClientPID = 0x6c0
TeGdiClientTID = 0x6c4
TeGdiThreadLocalInfo = 0x6c8
TeglDispatchTable = 0x7c4
TeglReserved1 = 0xb68
TeglReserved2 = 0xbdc
TeglSectionInfo = 0xbe0
TeglSection = 0xbe4
TeglTable = 0xbe8
TeglCurrentRC = 0xbec
TeglContext = 0xbf0
TeDeallocationStack = 0xe0c
TeTlsSlots = 0xe10
TeVdm = 0xf18
TeInstrumentation = 0xf2c
TeGdiBatchCount = 0xf70
TeGuaranteedStackBytes = 0xf78
TeTlsExpansionSlots = 0xf94
TeFlsData = 0xfb4
ThreadEnvironmentBlockLength = 0xfbc

/* TIME_FIELDS */
TfYear = 0x0
TfMonth = 0x2
TfDay = 0x4
TfHour = 0x6
TfMinute = 0x8
TfSecond = 0xa
TfMilliseconds = 0xc
TfWeekday = 0xe

/* KTHREAD */
ThType = 0x0
ThLock = 0x0
ThSize = 0x2
ThThreadControlFlags = 0x2
ThDebugActive = 0x3
ThSignalState = 0x4
ThInitialStack = 0x18
ThStackLimit = 0x1c
ThStackBase = 0x158
ThThreadLock = 0x24
ThServiceTable = 0x118
ThKernelStack = 0x20
ThAlerted = 0x5e
ThThreadFlags = 0xa0
ThTrapFrame = 0x110
ThApcState = 0x28
ThPriority = 0x5b
ThSwapBusy = 0x5d
ThContextSwitches = 0x48
ThState = 0x4c
ThProcess = 0x128
ThNpxState = 0x4d
ThWaitIrql = 0x4e
ThWaitMode = 0x4f
ThTeb = 0x74
ThTimer = 0x78
ThWin32Thread = 0x154
ThWaitTime = 0x6c
ThCombinedApcDisable = 0x70
ThKernelApcDisable = 0x70
ThSpecialApcDisable = 0x72
ThNextProcessor = 0x40
ThPreviousMode = 0xd7
ThPriorityDecrement = 0x122
ThAdjustReason = 0x42
ThAdjustIncrement = 0x43
ThAffinity = 0x12c
ThApcStateIndex = 0x11c
ThIdealProcessor = 0x11d
ThApcStatePointer = 0x130
ThSavedApcState = 0x138
ThWaitReason = 0x5a
ThSaturation = 0x123
ThLegoData = 0x184
KernelThreadObjectLength = 0x1b8

/* ETHREAD */

/* KTIMER */
TiType = 0x0
TiSize = 0x2
TiInserted = 0x3
TiSignalState = 0x4
TiDueTime = 0x10
TiTimerListEntry = 0x18
TiDpc = 0x20
TiPeriod = 0x24
TimerObjectLength = 0x28

/* TIME */
TmLowTime = 0x0
TmHighTime = 0x4

/* SYSTEM_CONTEXT_SWITCH_INFORMATION (relative to FindAny) */
TwFindAny = 0x0
TwFindIdeal = 0x8
TwFindLast = 0x4
TwIdleAny = 0xc
TwIdleCurrent = 0x10
TwIdleIdeal = 0x18
TwIdleLast = 0x14
TwPreemptAny = 0x1c
TwPreemptCurrent = 0x20
TwPreemptLast = 0x24
TwSwitchToIdle = 0x28

/* KUSER_SHARED_DATA */
UsTickCountMultiplier = 0x4
UsInterruptTime = 0x8
UsSystemTime = 0x14
UsTimeZoneBias = 0x20
UsImageNumberLow = 0x2c
UsImageNumberHigh = 0x2e
UsNtSystemRoot = 0x30
UsMaxStackTraceDepth = 0x238
UsCryptoExponent = 0x23c
UsTimeZoneId = 0x240
UsLargePageMinimum = 0x244
UsReserved2 = 0x248
UsNtProductType = 0x264
UsProductTypeIsValid = 0x268
UsNtMajorVersion = 0x26c
UsNtMinorVersion = 0x270
UsProcessorFeatures = 0x274
UsReserved1 = 0x2b4
UsReserved3 = 0x2b8
UsTimeSlip = 0x2bc
UsAlternativeArchitecture = 0x2c0
UsSystemExpirationDate = 0x2c8
UsSuiteMask = 0x2d0
UsKdDebuggerEnabled = 0x2d4
UsActiveConsoleId = 0x2d8
UsDismountCount = 0x2dc
UsComPlusPackage = 0x2e0
UsLastSystemRITEventTickCount = 0x2e4
UsNumberOfPhysicalPages = 0x2e8
UsSafeBootMode = 0x2ec
UsTestRetInstruction = 0x2f8
UsSystemCall = 0x300
UsSystemCallReturn = 0x304
UsSystemCallPad = 0x308
UsTickCount = 0x320
UsTickCountQuad = 0x320
UsWow64SharedInformation = 0x334

/* KWAIT_BLOCK offsets */
WbWaitListEntry = 0x0
WbThread = 0x8
WbObject = 0xc
WbNextWaitBlock = 0x10
WbWaitKey = 0x14
WbWaitType = 0x16
