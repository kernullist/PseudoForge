NTSTATUS NtCreateUserProcess(void)
{
  return PspAllocateProcess();
}
