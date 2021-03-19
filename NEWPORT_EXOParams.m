(venv) PS C:\>
>> (venv) PS C:\> ${21.1.7.2} | Format-EXOParams
>> WARNING: The names of some imported commands from the module 'Microsoft.PowerApps.Administration.PowerShell' include unapproved verbs that might make them less discoverable. To find the commands with unapproved verbs, run the Import-Module command again with the Verbose parameter. For a list of approved verbs, type Get-Verb.
>>
>> Exception             : System.Management.Automation.ParameterBindingException: The input object cannot be bound to any parameters for the command either because the command does not take pipeline input or the input and its properties
>>                         do not match any of the parameters that take pipeline input.
>> TargetObject          : PSGallery.version
>> CategoryInfo          : InvalidArgument: (PSGallery.version:ScriptBlock) [Format-EXOParams], ParameterBindingException
>> FullyQualifiedErrorId : InputObjectNotBound,Format-EXOParams
>> ErrorDetails          :
>> InvocationInfo        : System.Management.Automation.InvocationInfo
>> ScriptStackTrace      : at <ScriptBlock>, <No file>: line 1
>> PipelineIterationInfo : {1, 0}
>> PSMessageDetails      :
>> Exception             : System.Management.Automation.RuntimeException: You cannot call a method on a null-valued expression.
>>                            at CallSite.Target(Closure , CallSite , Object , String )
>>                            at System.Dynamic.UpdateDelegates.UpdateAndExecute2[T0,T1,TRet](CallSite site, T0 arg0, T1 arg1)
>>                            at System.Management.Automation.Interpreter.DynamicInstruction`3.Run(InterpretedFrame frame)
>>                            at System.Management.Automation.Interpreter.EnterTryCatchFinallyInstruction.Run(InterpretedFrame frame)
>> TargetObject          :
>> CategoryInfo          : InvalidOperation: (:) [], RuntimeException
>> FullyQualifiedErrorId : InvokeMethodOnNull
>> ErrorDetails          :
>> InvocationInfo        : System.Management.Automation.InvocationInfo
>> ScriptStackTrace      : at Format-EXOParams, C:\Users\UTLUSR\Documents\PowerShell\Modules\Microsoft365DSC\1.21.224.1\modules\M365DSCUtil.psm1: line 28
>>                         at <ScriptBlock>, <No file>: line 1
>> PipelineIterationInfo : {}
>> PSMessageDetails      :
>> Exception             : System.Management.Automation.RuntimeException: You cannot call a method on a null-valued expression.
>>                            at CallSite.Target(Closure , CallSite , Object , String )
>>                            at System.Dynamic.UpdateDelegates.UpdateAndExecute2[T0,T1,TRet](CallSite site, T0 arg0, T1 arg1)
>>                            at System.Management.Automation.Interpreter.DynamicInstruction`3.Run(InterpretedFrame frame)
>>                            at System.Management.Automation.Interpreter.EnterTryCatchFinallyInstruction.Run(InterpretedFrame frame)
>> TargetObject          :
>> CategoryInfo          : InvalidOperation: (:) [], RuntimeException
>> FullyQualifiedErrorId : InvokeMethodOnNull
>> ErrorDetails          :
>> InvocationInfo        : System.Management.Automation.InvocationInfo
>> ScriptStackTrace      : at Format-EXOParams, C:\Users\UTLUSR\Documents\PowerShell\Modules\Microsoft365DSC\1.21.224.1\modules\M365DSCUtil.psm1: line 29
>>                         at <ScriptBlock>, <No file>: line 1
>> PipelineIterationInfo : {}
>> PSMessageDetails      :
>> Exception             : System.Management.Automation.RuntimeException: You cannot call a method on a null-valued expression.
>>                            at CallSite.Target(Closure , CallSite , Object , String )
>>                            at System.Dynamic.UpdateDelegates.UpdateAndExecute2[T0,T1,TRet](CallSite site, T0 arg0, T1 arg1)
>>                            at System.Management.Automation.Interpreter.DynamicInstruction`3.Run(InterpretedFrame frame)
>>                            at System.Management.Automation.Interpreter.EnterTryCatchFinallyInstruction.Run(InterpretedFrame frame)
>> TargetObject          :
>> CategoryInfo          : InvalidOperation: (:) [], RuntimeException
>> FullyQualifiedErrorId : InvokeMethodOnNull
>> ErrorDetails          :
>> InvocationInfo        : System.Management.Automation.InvocationInfo
>> ScriptStackTrace      : at Format-EXOParams, C:\Users\UTLUSR\Documents\PowerShell\Modules\Microsoft365DSC\1.21.224.1\modules\M365DSCUtil.psm1: line 30
>>                         at <ScriptBlock>, <No file>: line 1
>> PipelineIterationInfo : {}
>> PSMessageDetails      :^B
>> (venv) PS C:\> ${21.1.7.2} | Format-EXOParams
>> WARNING: The names of some imported commands from the module 'Microsoft.PowerApps.Administration.PowerShell' include unapproved verbs that might make them less discoverable. To find the commands with unapproved verbs, run the Import-Module command again with the Verbose parameter. For a list of approved verbs, type Get-Verb.
>>
>> Exception             : System.Management.Automation.ParameterBindingException: The input object cannot be bound to any parameters for the command either because the command does not take pipeline input or the input and its properties
>>                         do not match any of the parameters that take pipeline input.
>> TargetObject          : PSGallery.version
>> CategoryInfo          : InvalidArgument: (PSGallery.version:ScriptBlock) [Format-EXOParams], ParameterBindingException
>> FullyQualifiedErrorId : InputObjectNotBound,Format-EXOParams
>> ErrorDetails          :
>> InvocationInfo        : System.Management.Automation.InvocationInfo
>> ScriptStackTrace      : at <ScriptBlock>, <No file>: line 1
>> PipelineIterationInfo : {1, 0}
>> PSMessageDetails      :
>> Exception             : System.Management.Automation.RuntimeException: You cannot call a method on a null-valued expression.
>>                            at CallSite.Target(Closure , CallSite , Object , String )
>>                            at System.Dynamic.UpdateDelegates.UpdateAndExecute2[T0,T1,TRet](CallSite site, T0 arg0, T1 arg1)
>>                            at System.Management.Automation.Interpreter.DynamicInstruction`3.Run(InterpretedFrame frame)
>>                            at System.Management.Automation.Interpreter.EnterTryCatchFinallyInstruction.Run(InterpretedFrame frame)
>> TargetObject          :
>> CategoryInfo          : InvalidOperation: (:) [], RuntimeException
>> FullyQualifiedErrorId : InvokeMethodOnNull
>> ErrorDetails          :
>> InvocationInfo        : System.Management.Automation.InvocationInfo
>> ScriptStackTrace      : at Format-EXOParams, C:\Users\UTLUSR\Documents\PowerShell\Modules\Microsoft365DSC\1.21.224.1\modules\M365DSCUtil.psm1: line 28
>>                         at <ScriptBlock>, <No file>: line 1
>> PipelineIterationInfo : {}
>> PSMessageDetails      :
>> Exception             : System.Management.Automation.RuntimeException: You cannot call a method on a null-valued expression.
>>                            at CallSite.Target(Closure , CallSite , Object , String )
>>                            at System.Dynamic.UpdateDelegates.UpdateAndExecute2[T0,T1,TRet](CallSite site, T0 arg0, T1 arg1)
>>                            at System.Management.Automation.Interpreter.DynamicInstruction`3.Run(InterpretedFrame frame)
>>                            at System.Management.Automation.Interpreter.EnterTryCatchFinallyInstruction.Run(InterpretedFrame frame)
>> TargetObject          :
>> CategoryInfo          : InvalidOperation: (:) [], RuntimeException
>> FullyQualifiedErrorId : InvokeMethodOnNull
>> ErrorDetails          :
>> InvocationInfo        : System.Management.Automation.InvocationInfo
>> ScriptStackTrace      : at Format-EXOParams, C:\Users\UTLUSR\Documents\PowerShell\Modules\Microsoft365DSC\1.21.224.1\modules\M365DSCUtil.psm1: line 29
>>                         at <ScriptBlock>, <No file>: line 1
>> PipelineIterationInfo : {}
>> PSMessageDetails      :
>> Exception             : System.Management.Automation.RuntimeException: You cannot call a method on a null-valued expression.
>>                            at CallSite.Target(Closure , CallSite , Object , String )
>>                            at System.Dynamic.UpdateDelegates.UpdateAndExecute2[T0,T1,TRet](CallSite site, T0 arg0, T1 arg1)
>>                            at System.Management.Automation.Interpreter.DynamicInstruction`3.Run(InterpretedFrame frame)
>>                            at System.Management.Automation.Interpreter.EnterTryCatchFinallyInstruction.Run(InterpretedFrame frame)
>> TargetObject          :
>> CategoryInfo          : InvalidOperation: (:) [], RuntimeException
>> FullyQualifiedErrorId : InvokeMethodOnNull
>> ErrorDetails          :
>> InvocationInfo        : System.Management.Automation.InvocationInfo
>> ScriptStackTrace      : at Format-EXOParams, C:\Users\UTLUSR\Documents\PowerShell\Modules\Microsoft365DSC\1.21.224.1\modules\M365DSCUtil.psm1: line 30
>>                         at <ScriptBlock>, <No file>: line 1
>> PipelineIterationInfo : {}
>> PSMessageDetails      :^F^Q^C
(venv) PS C:\>
