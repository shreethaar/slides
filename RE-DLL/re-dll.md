---
marp: true
theme: gaia
paginate: true
backgroundColor: #313045
color: white
---

<style>
.logo-row {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 40px;
  margin-top: 30px;
}
.logo-row img {
  height: 160px;
}
</style>

<!-- _class: lead -->
# Dissecting DLL with Static and Dynamic Analysis
Shreethaar Arunagirinathan
@0x251e

<div class="logo-row">
  <img src="logo.png">
  <img src="logo2.png">
  <img src="logo3.png">
</div>

---

### ./whoami

- Shreethaar Arunagirinathan 
- Computer Science @ UUM
- MCC 2024 Alumni 
- CTFs @ RE:UN10N 
    - DFIR
    - RE 
    - OSINT

![bg right:45%](0x251e.png)

---

### ./case_study

<style>
div.twocols {
  margin-top: 35px;
  column-count: 2;
  font-size: 0.65em;
}
div.twocols p:first-child,
div.twocols h1:first-child,
div.twocols h2:first-child,
div.twocols ul:first-child,
div.twocols ul li:first-child,
div.twocols ul li p:first-child {
  margin-top: 0 !important;
}
div.twocols p.break {
  break-before: column;
  margin-top: 0;
}
div.twocols ul li {
  font-size: 0.85em;
  line-height: 1.5;
  margin-bottom: 0.4em;
}
.reference {
  font-size: 0.7em;
  color: #cccccc;
  margin-top: 10px;
  text-align: center;
}
</style>

<div class="twocols">

- **Target:** WinSCP users (430K searches/3 months) via fake Google Ads
- User downloads `WinSCP_v.6.1.zip` → runs `setup.exe`
- Appears legitimate: setup.exe = signed pythonw.exe ✅
- Hidden threat: python311.dll = MALICIOUS ❌

**The Deception**
- Traditional analysis: "Legitimate signed binary = safe"
- Reality: Malicious DLL sideloaded by legitimate process
- Full system compromise through DLL hijacking
- Persistence via scheduled tasks + more DLL chains

<p class="break"></p>

![right height:400px](https://www.iaesjournal.com/wp-content/uploads/2023/11/hacking.webp)

<p class="reference">References: <a href="https://www.iaesjournal.com/4980-2/">https://www.iaesjournal.com/4980-2/</a></p>
</div>

---

### ./why_reversing_dll_matters
- Modern malware uses DLL to employ various tactics
    - [MITRE ATT&CK Hijack Execution Flow: DLL](https://attack.mitre.org/techniques/T1574/001/)
- Common in reflecive and process injections
- More stealthy behavior and modular payloads
- DLL is one of the top 5 file types listed in MalwareBazaar 
- Vulnerabilities analysis that lead to supply chain risks
- Understand how applications interacts with external libraries

---

### ./what_is_dll
<style>
section ul {
    font-size: 0.75em !important;
    line-height: 1.4;
}
section ul li {
    margin-bottom: 0.3em;
}
</style>

- DLL (Dynamic Link Library) contains code and data which used by more than one program at the same time
- Contains **exported functions** to be called by other modules
- Any process that uses Windows API uses dynamic linking:
    - Comdlg32 DLL use for dialog box related functions (GetOpenFileName, GetSaveFileName)
- Dynamic linking allows a module to include only the information needed to locate an exported DLL function at loadtime or runtime 
- Benefits of using DLL:
    - Reduce memory and disk usage as duplication of code is reduced
    - Promotes modular architecture, eases deployment and installation
- Security Matters with DLL:
    - Code sharing: Multiple applications can use the same DLL
    - Runtime Loading: DLLs loaded when needed (attack opportunity)
    - Modularity: Can be replaced or hijacked without changing main executable
---

### ./how_dll_works



---

### ./create_simple_dll 


---

### ./structure_of_dll


---


