Interceptor.attach(Module.findExportByName(null, "memcmp"), {
  onEnter: function (args) {
    // Bypass memory checks
  }
});

Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
  onEnter: function (args) {
    console.log('[+] ptrace called — bypassing');
    args[0] = ptr(0);  // PT_DENY_ATTACH replaced
  },
  onLeave: function (retval) {
    retval.replace(0);
  }
});

Module.enumerateRanges('r-x').forEach(function (range) {
  Memory.scan(range.base, range.size, '7f 45 4c 46', {
    onMatch: function (addr, size) {
      console.log('[ELF] Found ELF header at: ' + addr);
    }
  });
});
