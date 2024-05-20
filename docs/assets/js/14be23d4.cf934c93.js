"use strict";(self.webpackChunknugetdefense_docs=self.webpackChunknugetdefense_docs||[]).push([[747],{280:(e,n,i)=>{i.r(n),i.d(n,{assets:()=>o,contentTitle:()=>r,default:()=>h,frontMatter:()=>t,metadata:()=>c,toc:()=>d});var s=i(7624),l=i(4552);const t={title:"CLI Reference",sidebar_position:4},r="CLI Interface",c={id:"cli-reference",title:"CLI Reference",description:"If you want to use NuGetDefense directly, maintain a single global installation, or set up NuGetDefense in your CI environment.",source:"@site/docs/cli-reference.mdx",sourceDirName:".",slug:"/cli-reference",permalink:"/NuGetDefense/docs/cli-reference",draft:!1,unlisted:!1,editUrl:"https://github.com/digitalcoyote/NuGetDefenseDocs/tree/master/docs/cli-reference.mdx",tags:[],version:"current",sidebarPosition:4,frontMatter:{title:"CLI Reference",sidebar_position:4},sidebar:"tutorialSidebar",previous:{title:"Configuration",permalink:"/NuGetDefense/docs/configuration"},next:{title:"NuGetDefense.Lib",permalink:"/NuGetDefense/docs/API Reference/NuGetDefense.Lib"}},o={},d=[{value:"Installation",id:"installation",level:2},{value:"Help",id:"help",level:3},{value:"Target Project or Solution",id:"target-project-or-solution",level:3},{value:"Target Framework Moniker",id:"target-framework-moniker",level:3},{value:"Settings File",id:"settings-file",level:3},{value:"Vulnerability Data Bin",id:"vulnerability-data-bin",level:3},{value:"Warn Only",id:"warn-only",level:3},{value:"Check Transitive Dependencies",id:"check-transitive-dependencies",level:3},{value:"Ignore CVE&#39;s",id:"ignore-cves",level:3},{value:"Ignore Packages",id:"ignore-packages",level:3},{value:"Cache Location",id:"cache-location",level:3},{value:"Update",id:"update",level:2},{value:"Recreate-NVD",id:"recreate-nvd",level:2}];function a(e){const n={a:"a",admonition:"admonition",code:"code",h1:"h1",h2:"h2",h3:"h3",li:"li",p:"p",ul:"ul",...(0,l.M)(),...e.components};return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(n.h1,{id:"cli-interface",children:"CLI Interface"}),"\n",(0,s.jsx)(n.p,{children:"If you want to use NuGetDefense directly, maintain a single global installation, or set up NuGetDefense in your CI environment."}),"\n",(0,s.jsx)(n.h2,{id:"installation",children:"Installation"}),"\n",(0,s.jsxs)(n.p,{children:["Typical CLI usage of NuGetDefense will use the .Net Global Tool installable via:\n",(0,s.jsx)(n.code,{children:"dotnet tool install --global NuGetDefense.Tool"})]}),"\n",(0,s.jsxs)(n.p,{children:["Alternatively, you can directly download the NuGetDefense release directly from gitHub and run it using:\n",(0,s.jsx)(n.code,{children:"dotnet NuGetDefense.dll <options>"})]}),"\n",(0,s.jsx)(n.h3,{id:"help",children:"Help"}),"\n",(0,s.jsxs)(n.p,{children:[(0,s.jsx)(n.code,{children:"nugedefense -?"}),"\nIf you ever need a quick reference this will list all the supported options and aliases"]}),"\n",(0,s.jsx)(n.h3,{id:"target-project-or-solution",children:"Target Project or Solution"}),"\n",(0,s.jsx)(n.p,{children:(0,s.jsx)(n.code,{children:"--project-file <path-to-file>"})}),"\n",(0,s.jsx)(n.p,{children:"This is a relative or absolute path to the project or solution you want to scan. Solution files will cause all projects in the solution to be scanned."}),"\n",(0,s.jsx)(n.p,{children:"Aliases"}),"\n",(0,s.jsxs)(n.ul,{children:["\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"-p"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--project"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--solution"})}),"\n"]}),"\n",(0,s.jsx)(n.h3,{id:"target-framework-moniker",children:"Target Framework Moniker"}),"\n",(0,s.jsx)(n.p,{children:(0,s.jsx)(n.code,{children:"--target-framework-moniker <tfm>"})}),"\n",(0,s.jsxs)(n.p,{children:["This is the tfm value passed to the dotnet sdk when resolving dependency version for ",(0,s.jsx)(n.a,{href:"https://docs.microsoft.com/en-us/dotnet/core/project-sdk/overview",children:"sdk style project"}),". This allows NuGetDefense to detect the exact versions of dependencies that will be used at build."]}),"\n",(0,s.jsx)(n.p,{children:"Aliases"}),"\n",(0,s.jsxs)(n.ul,{children:["\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--framework"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--tfm"})}),"\n"]}),"\n",(0,s.jsx)(n.h3,{id:"settings-file",children:"Settings File"}),"\n",(0,s.jsx)(n.p,{children:(0,s.jsx)(n.code,{children:"--settings-file <path-to-file>"})}),"\n",(0,s.jsxs)(n.p,{children:["Absolute or relative path to the settings file (",(0,s.jsx)(n.code,{children:"NuGetDefense.json"})," by default). Any settings passed in via other options will override the values read from this file."]}),"\n",(0,s.jsx)(n.p,{children:"Aliases"}),"\n",(0,s.jsxs)(n.ul,{children:["\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--nugetdefense-settings"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--nugetdefense-json"})}),"\n"]}),"\n",(0,s.jsx)(n.h3,{id:"vulnerability-data-bin",children:"Vulnerability Data Bin"}),"\n",(0,s.jsx)(n.p,{children:(0,s.jsx)(n.code,{children:"--vulnerability-data-bin <path-to-file>"})}),"\n",(0,s.jsx)(n.admonition,{type:"caution",children:(0,s.jsxs)(n.p,{children:[(0,s.jsx)(n.a,{href:"https://github.com/digitalcoyote/NuGetDefense/issues/70",children:"Issue #70"}),"\nThis option currently does nothing. Feel free to submit a PR or comment to increase the priority of this issue."]})}),"\n",(0,s.jsxs)(n.p,{children:["Absolute or relative path to the NVD binary store (",(0,s.jsx)(n.code,{children:"vulnerabilityData.bin"})," by default). This is updated automatically from the ",(0,s.jsx)(n.a,{href:"https://nvd.nist.gov/",children:"National Vulnerability Database"})]}),"\n",(0,s.jsx)(n.p,{children:"Aliases"}),"\n",(0,s.jsxs)(n.ul,{children:["\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--nvd-data"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--nvd-data-bin"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--nvd-bin"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--vulnerability-bin"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--vulnerability-data"})}),"\n"]}),"\n",(0,s.jsx)(n.h3,{id:"warn-only",children:"Warn Only"}),"\n",(0,s.jsx)(n.p,{children:(0,s.jsx)(n.code,{children:"--warn-only"})}),"\n",(0,s.jsx)(n.admonition,{type:"tip",children:(0,s.jsx)(n.p,{children:"This is generally used to prevent breaking builds in an MSBuild ExecTask when vulnerabilities are found but is also useful for some CI environments."})}),"\n",(0,s.jsx)(n.p,{children:"Emits MSBuild Warn messages instead of Error messages."}),"\n",(0,s.jsx)(n.p,{children:"Aliases"}),"\n",(0,s.jsxs)(n.ul,{children:["\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--do-not-break"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--warn"})}),"\n"]}),"\n",(0,s.jsx)(n.h3,{id:"check-transitive-dependencies",children:"Check Transitive Dependencies"}),"\n",(0,s.jsx)(n.p,{children:(0,s.jsx)(n.code,{children:"--check-project-references"})}),"\n",(0,s.jsx)(n.p,{children:"Enables scanning projects referenced by the target project"}),"\n",(0,s.jsx)(n.p,{children:"Aliases"}),"\n",(0,s.jsxs)(n.ul,{children:["\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--check-referenced-projects"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--check-referenced"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--check-references"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--references"})}),"\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--referenced-projects"})}),"\n"]}),"\n",(0,s.jsx)(n.h3,{id:"ignore-cves",children:"Ignore CVE's"}),"\n",(0,s.jsx)(n.p,{children:(0,s.jsx)(n.code,{children:"--ignore-cves <CVEs-to-ignore>"})}),"\n",(0,s.jsx)(n.p,{children:"List of vulnerabilities to ignore when reporting vulnerabilities."}),"\n",(0,s.jsx)(n.p,{children:"Aliases"}),"\n",(0,s.jsxs)(n.ul,{children:["\n",(0,s.jsx)(n.li,{children:(0,s.jsx)(n.code,{children:"--ignore-vulns"})}),"\n"]}),"\n",(0,s.jsx)(n.h3,{id:"ignore-packages",children:"Ignore Packages"}),"\n",(0,s.jsx)(n.p,{children:(0,s.jsx)(n.code,{children:"--ignore-packages <packageids-to-ignore>"})}),"\n",(0,s.jsx)(n.p,{children:"List of vulnerabilities to ignore when reporting vulnerabilities."}),"\n",(0,s.jsx)(n.h3,{id:"cache-location",children:"Cache Location"}),"\n",(0,s.jsx)(n.p,{children:(0,s.jsx)(n.code,{children:"--cache-location <path/to/file>"})}),"\n",(0,s.jsx)(n.p,{children:"Absolute or relative path to the file used for caching remote vulnerability scan results."}),"\n",(0,s.jsx)(n.h2,{id:"update",children:"Update"}),"\n",(0,s.jsx)(n.admonition,{type:"info",children:(0,s.jsx)(n.p,{children:"This command needs documentation still"})}),"\n",(0,s.jsx)(n.h2,{id:"recreate-nvd",children:"Recreate-NVD"}),"\n",(0,s.jsx)(n.admonition,{type:"info",children:(0,s.jsx)(n.p,{children:"This command needs documentation still"})})]})}function h(e={}){const{wrapper:n}={...(0,l.M)(),...e.components};return n?(0,s.jsx)(n,{...e,children:(0,s.jsx)(a,{...e})}):a(e)}},4552:(e,n,i)=>{i.d(n,{M:()=>r});var s=i(1504);const l={},t=s.createContext(l);function r(e){const n=s.useContext(t);return s.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}}}]);