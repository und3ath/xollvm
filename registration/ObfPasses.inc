//===-- ObfPasses.inc - canonical obfuscator pass/analysis table -*- C++ -*-===//
//
// THE single source of truth for the obfuscator's registered names. Consumed
// by registration/PluginEntry.cpp for both build modes (loadable plugin and
// static in-tree extension). No PassRegistry.def mirror anymore.
//
// An include site defines any subset of the macros
// below; undefined ones expand to nothing. All are #undef'd at the end so the
// file may be included repeatedly (once per macro context).
//
// NOTE: the analyses must be registered too, not just the passes -- the
// function driver queries FunctionObfContextAnalysis and the module pass
// queries ObfReportAnalysis, so a plugin that registers only the pass names
// asserts at run time ("analysis pass was not registered prior to being
// queried").
//
//===----------------------------------------------------------------------===//

#ifndef OBF_MODULE_ANALYSIS
#define OBF_MODULE_ANALYSIS(NAME, CREATE)
#endif
#ifndef OBF_FUNCTION_ANALYSIS
#define OBF_FUNCTION_ANALYSIS(NAME, CREATE)
#endif
#ifndef OBF_MODULE_PASS
#define OBF_MODULE_PASS(NAME, CREATE)
#endif
#ifndef OBF_FUNCTION_PASS
#define OBF_FUNCTION_PASS(NAME, CREATE)
#endif

OBF_MODULE_ANALYSIS("obf-annotations", ObfuscationAnnotationAnalysis())
OBF_MODULE_ANALYSIS("obf-report", ObfReportAnalysis())

OBF_FUNCTION_ANALYSIS("function-obf-context", FunctionObfContextAnalysis())

OBF_MODULE_PASS("obfuscation", ObfuscationModulePass())
OBF_MODULE_PASS("obf-dump-config", ObfDumpConfigPass())
OBF_MODULE_PASS("obf-metrics", ObfMetricsPass())

OBF_FUNCTION_PASS("obfuscation-fn", ObfuscationFunctionDriverPass())

#undef OBF_MODULE_ANALYSIS
#undef OBF_FUNCTION_ANALYSIS
#undef OBF_MODULE_PASS
#undef OBF_FUNCTION_PASS
