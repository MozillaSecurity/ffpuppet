define quit_with_code
  if $_siginfo
    quit 128+$_siginfo.si_signo
  else
    quit $_exitcode
  end
end

handle SIG38 nostop noprint pass
set breakpoint pending on
set confirm off
set prompt
maint set internal-error quit yes
maint set internal-error corefile no
set backtrace limit 25
set print elements 10
set python print-stack full
set trace-commands on
