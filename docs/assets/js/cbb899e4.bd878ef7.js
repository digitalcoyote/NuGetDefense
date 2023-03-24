"use strict";(self.webpackChunknugetdefense_docs=self.webpackChunknugetdefense_docs||[]).push([[196],{3905:(e,t,n)=>{n.d(t,{Zo:()=>p,kt:()=>c});var a=n(7294);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function l(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?l(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):l(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function o(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},l=Object.keys(e);for(a=0;a<l.length;a++)n=l[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var l=Object.getOwnPropertySymbols(e);for(a=0;a<l.length;a++)n=l[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var s=a.createContext({}),d=function(e){var t=a.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},p=function(e){var t=d(e.components);return a.createElement(s.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},k=a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,l=e.originalType,s=e.parentName,p=o(e,["components","mdxType","originalType","parentName"]),k=d(n),c=r,g=k["".concat(s,".").concat(c)]||k[c]||u[c]||l;return n?a.createElement(g,i(i({ref:t},p),{},{components:n})):a.createElement(g,i({ref:t},p))}));function c(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var l=n.length,i=new Array(l);i[0]=k;var o={};for(var s in t)hasOwnProperty.call(t,s)&&(o[s]=t[s]);o.originalType=e,o.mdxType="string"==typeof e?e:r,i[1]=o;for(var d=2;d<l;d++)i[d]=n[d];return a.createElement.apply(null,i)}return a.createElement.apply(null,n)}k.displayName="MDXCreateElement"},9326:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>s,contentTitle:()=>i,default:()=>u,frontMatter:()=>l,metadata:()=>o,toc:()=>d});var a=n(7462),r=(n(7294),n(3905));const l={title:"Configuration",sidebar_position:3},i=void 0,o={unversionedId:"configuration",id:"configuration",title:"Configuration",description:"This documentation is a WIP and gives only a brief explanation of what each field in the NuGetDefense.json configuration file does and what values they accept.",source:"@site/docs/configuration.mdx",sourceDirName:".",slug:"/configuration",permalink:"/NuGetDefense/docs/configuration",draft:!1,editUrl:"https://github.com/digitalcoyote/NuGetDefenseDocs/tree/master/docs/configuration.mdx",tags:[],version:"current",sidebarPosition:3,frontMatter:{title:"Configuration",sidebar_position:3},sidebar:"tutorialSidebar",previous:{title:"Getting Started",permalink:"/NuGetDefense/docs/getting-started"},next:{title:"CLI Reference",permalink:"/NuGetDefense/docs/cli-reference"}},s={},d=[{value:"WarnOnly",id:"warnonly",level:2},{value:"Accepted Values",id:"accepted-values",level:4},{value:"VulnerabilityReports",id:"vulnerabilityreports",level:2},{value:"CheckTransitiveDependencies",id:"checktransitivedependencies",level:2},{value:"CheckReferencedProjects",id:"checkreferencedprojects",level:2},{value:"ErrorSettings",id:"errorsettings",level:2},{value:"ErrorSeverityThreshold",id:"errorseveritythreshold",level:3},{value:"Cvss3Threshold",id:"cvss3threshold",level:3},{value:"IgnoredPackages",id:"ignoredpackages",level:3},{value:"IgnoredCvEs",id:"ignoredcves",level:3},{value:"AllowedPackages / WhiteListedPackages",id:"allowedpackages--whitelistedpackages",level:3},{value:"BlockedPackages / BlackListedPackages",id:"blockedpackages--blacklistedpackages",level:3},{value:"OssIndex / GitHubAdvisoryDatabase",id:"ossindex--githubadvisorydatabase",level:2},{value:"NVD",id:"nvd",level:2},{value:"SensitivePackages",id:"sensitivepackages",level:2},{value:"Log / Logs",id:"log--logs",level:2},{value:"CacheLocation",id:"cachelocation",level:2}],p={toc:d};function u(e){let{components:t,...n}=e;return(0,r.kt)("wrapper",(0,a.Z)({},p,n,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("admonition",{type:"caution"},(0,r.kt)("p",{parentName:"admonition"},"This documentation is a WIP and gives only a brief explanation of what each field in the NuGetDefense.json configuration file does and what values they accept.")),(0,r.kt)("h1",{id:"configuring-nugetdefense"},"Configuring NuGetDefense"),(0,r.kt)("p",null,"NuGetDefense can run without any prior configuration. On the first run, it will generate a config file in the ",(0,r.kt)("a",{parentName:"p",href:"https://learn.microsoft.com/en-us/dotnet/api/system.environment.specialfolder"},"AppData Special Folder")," with the defaults used when no configuration is found. For more control over specific projects and solutions, you can add a NuGetDefense.json config file to the directory with your project or solution file and it will be used instead."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-json",metastring:'title="NuGetDefense.json"',title:'"NuGetDefense.json"'},'{\n  "WarnOnly": false,\n  "VulnerabilityReports": {\n    "OutputTextReport": true\n  },\n  "CheckTransitiveDependencies": true,\n  "CheckReferencedProjects": false,\n  "ErrorSettings": {\n    "ErrorSeverityThreshold": "any",\n    "Cvss3Threshold": -1,\n    "IgnoredPackages": [\n      {\n        "Id": "NugetDefense"\n      }\n    ],\n    "IgnoredCvEs": [],\n    "AllowedPackages": [],\n    "WhiteListedPackages": [],\n    "BlockedPackages": [],\n    "BlacklistedPackages": []\n  },\n  "OssIndex": {\n    "ApiToken": "",\n    "Username": "",\n    "Enabled": true,\n    "BreakIfCannotRun": true\n  },\n  "GitHubAdvisoryDatabase": {\n    "ApiToken": "",\n    "Username": "",\n    "Enabled": true,\n    "BreakIfCannotRun": false\n  },\n  "NVD": {\n    "SelfUpdate": false,\n    "TimeoutInSeconds": 15,\n    "Enabled": true,\n    "BreakIfCannotRun": true\n  },\n  "SensitivePackages": []\n}\n\n')),(0,r.kt)("h2",{id:"warnonly"},"WarnOnly"),(0,r.kt)("p",null,"When enabled, NuGetDefense will always return an exit code of 0, and will output msbuild warning messages instead of msBuild Error Messages"),(0,r.kt)("h4",{id:"accepted-values"},"Accepted Values"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"true"),(0,r.kt)("td",{parentName:"tr",align:null},"Enables WarnOnly mode preventing errors wehn vulnerabilities are reporting from the msBuild")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"false"),(0,r.kt)("td",{parentName:"tr",align:null},"Returns errors and a non-zero exit code when vulnerabilities are reported. This will break the build.msBuild")))),(0,r.kt)("h2",{id:"vulnerabilityreports"},"VulnerabilityReports"),(0,r.kt)("p",null,"VulnerabilityReports allows exporting reports generated by nugetdefense with details from the scan. There are a few report types available. Any reports omitted from these settings is disabled."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Report Option"),(0,r.kt)("th",{parentName:"tr",align:null},"Values Accepted"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"JsonReportPath"),(0,r.kt)("td",{parentName:"tr",align:null},"Any Valid File Path"),(0,r.kt)("td",{parentName:"tr",align:null},"Exports the VulnerabilityReport in JSON format to the provided path.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"OutputTextReport"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"true")," or ",(0,r.kt)("inlineCode",{parentName:"td"},"false")),(0,r.kt)("td",{parentName:"tr",align:null},"Outputs the a human readable VulnerabilityReport to the console.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"XmlReportPath"),(0,r.kt)("td",{parentName:"tr",align:null},"Any Valid File Path"),(0,r.kt)("td",{parentName:"tr",align:null},"Outputs the VulnerabilityReport in XML format to the provided path.")))),(0,r.kt)("h2",{id:"checktransitivedependencies"},"CheckTransitiveDependencies"),(0,r.kt)("p",null,"Transitive dependency checking relies on ",(0,r.kt)("inlineCode",{parentName:"p"},"dotnet list --transitive")," and adds any versions found in that list to the packages to be scanned."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"true"),(0,r.kt)("td",{parentName:"tr",align:null},"Enables scanning transitive dependencies (dependencies of the packages you have referenced that are automatically referenced in your project).")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"false"),(0,r.kt)("td",{parentName:"tr",align:null},"Disabled transitive dependency scanning.")))),(0,r.kt)("h2",{id:"checkreferencedprojects"},"CheckReferencedProjects"),(0,r.kt)("p",null,"Referenced project scanning works when the project file is scanned. Any packages referenced in those projects are scanned as well."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"true"),(0,r.kt)("td",{parentName:"tr",align:null},"Enables scanning project references.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"false"),(0,r.kt)("td",{parentName:"tr",align:null},"Disabled scanning project references.")))),(0,r.kt)("h2",{id:"errorsettings"},"ErrorSettings"),(0,r.kt)("p",null,"Error settings generally handle how errors for vulnerabilities are handled.packages"),(0,r.kt)("h3",{id:"errorseveritythreshold"},"ErrorSeverityThreshold"),(0,r.kt)("p",null,"Human readable levels for vulnerability severities. Each level corresponds to a CVSS score range. Scores below that range are ignored."),(0,r.kt)("p",null,"::: caution\nThis setting is not compatible with Cvss3Threshold\n:::"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Severityy"),(0,r.kt)("th",{parentName:"tr",align:null},"CVSS Score"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"any"),(0,r.kt)("td",{parentName:"tr",align:null},"N/A - ",(0,r.kt)("inlineCode",{parentName:"td"},"any")," disables  severity thresholds")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"None"),(0,r.kt)("td",{parentName:"tr",align:null},"CVSS3 score 0 - Only vulnerabilities without a CVSS score are ignored")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Low"),(0,r.kt)("td",{parentName:"tr",align:null},"CVSS3 score 0.1 - 3.9")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Medium"),(0,r.kt)("td",{parentName:"tr",align:null},"CVSS3 score 4.0 - 6.9")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"High"),(0,r.kt)("td",{parentName:"tr",align:null},"CVSS3 score 7.0 - 8.9")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Critical"),(0,r.kt)("td",{parentName:"tr",align:null},"CVSS3 score 9.0 - 10.0")))),(0,r.kt)("h3",{id:"cvss3threshold"},"Cvss3Threshold"),(0,r.kt)("p",null,"CSSV3 Score threshold for ignoring vulnerabilities."),(0,r.kt)("p",null,"::: caution\nThis setting is not compatible with ErrorSeverityThreshold\n:::"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"0 to 10.0"),(0,r.kt)("td",{parentName:"tr",align:null},"Ignores all vulnerabilities with a CVSS3 score lower than the threshold. Also Ignores All Vulnerabilities without a CVSS3 score.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"-1"),(0,r.kt)("td",{parentName:"tr",align:null},"Disables the threshold.")))),(0,r.kt)("h3",{id:"ignoredpackages"},"IgnoredPackages"),(0,r.kt)("p",null,"An array of packages to be ignored."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Id"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Required")," Id of the package to ignore")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Version"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Optional")," Version of the package to ignore. If no version is set, all versions of the package are ignored.")))),(0,r.kt)("p",null,"ex."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-json"},'[\n    {\n        "Id": "NugetDefense",\n        "Version": "1.2.3"\n    },\n    {\n        "Id": "InternalPackage.Invulnerable"\n    }\n]\n')),(0,r.kt)("h3",{id:"ignoredcves"},"IgnoredCvEs"),(0,r.kt)("p",null,"Array of CVE's or Vulenrability ID's to ingore when scanning."),(0,r.kt)("p",null,"ex. ",(0,r.kt)("inlineCode",{parentName:"p"},'["CVE-1234-1234","sonatype-1234-01234","GHSA-1234-abc9-abcd"]')),(0,r.kt)("h3",{id:"allowedpackages--whitelistedpackages"},"AllowedPackages / WhiteListedPackages"),(0,r.kt)("p",null,"This is an AllowList/WhiteList of packages that are allowed to be installed in the project. This is generally intended for CI use to prevent the addition of unapproved packages to a project. AllowedPackages is the official name of this setting, but for backwards compatability and non-english speaking users, WhiteListedPackages is also usable."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Id"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Required")," Id of the package to ignore")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Version"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Optional")," Version of the package to ignore. If no version is set, all versions of the package are ignored.")))),(0,r.kt)("p",null,"ex."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-json"},'[\n    {\n        "Id": "NugetDefense",\n        "Version": "1.2.3"\n    },\n    {\n        "Id": "InternalPackage.Invulnerable"\n    }\n]\n')),(0,r.kt)("h3",{id:"blockedpackages--blacklistedpackages"},"BlockedPackages / BlackListedPackages"),(0,r.kt)("p",null,"This is an AllowList/WhiteList of packages that are allowed to be installed in the project. This is generally intended for CI use to prevent the addition of unapproved packages to a project. AllowedPackages is the official name of this setting, but for backwards compatability and non-english speaking users, WhiteListedPackages is also usable."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Id"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Required")," Id of the package to ignore")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Version"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Optional")," Version of the package to ignore. If no version is set, all versions of the package are ignored.")))),(0,r.kt)("p",null,"ex."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-json"},'[\n    {\n        "Id": "NugetDefense",\n        "Version": "1.2.3"\n    },\n    {\n        "Id": "InternalPackage.Invulnerable"\n    }\n]\n')),(0,r.kt)("h2",{id:"ossindex--githubadvisorydatabase"},"OssIndex / GitHubAdvisoryDatabase"),(0,r.kt)("p",null," OSSIndex and GitHubAdvisoryDatabase are remote vulnerability sources and information about your packages must be sent up to their servers to gather information about the known vulnerabilities for them. They share teh same configuration settings. In general it's advisable to setup an account to access remote vulnerability services. GitHubAdvisoryDatabase does not work without one, but rewuires NO permissions. OSSindex provides more useful info with an account."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"APIToken"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Required For GitHubAdvisoryDatabase")," Password/API Token/Secret for accessing the API using your account")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Username"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Optional")," Username of the account used to access the remote vulnerability source")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Enabled"),(0,r.kt)("td",{parentName:"tr",align:null},"Enables using this vulnerability source. If not present or Disabled, this source will not be used to scan your packages.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"BreakIfCannotRun"),(0,r.kt)("td",{parentName:"tr",align:null},"If enabled, throws an error if the source cannot be run. This could be caused by aPI limits or network errors.")))),(0,r.kt)("h2",{id:"nvd"},"NVD"),(0,r.kt)("p",null,"  NVD is an offline copy of the National Vulnerability Database that is optionally self-updating. This is the least reliable source for vulnerability scanning since it has an automated update/parsing process."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"SelfUpdate"),(0,r.kt)("td",{parentName:"tr",align:null},"If Enabled, attempts to update the offile source before scanning.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"TimeoutInSeconds"),(0,r.kt)("td",{parentName:"tr",align:null},"Timeout to use when retrieving the latest vulnerabilities.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Enabled"),(0,r.kt)("td",{parentName:"tr",align:null},"Enables using this vulnerability source. If not present or Disabled, this source will not be used to scan your packages.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"BreakIfCannotRun"),(0,r.kt)("td",{parentName:"tr",align:null},"If enabled, throws an error if the source cannot be run. This could be caused by aPI limits or network errors.")))),(0,r.kt)("h2",{id:"sensitivepackages"},"SensitivePackages"),(0,r.kt)("p",null," Packages in this array are not sent to any remote vulnerability source but will still be scanned against the embedded NVD source."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Id"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Required")," Id of the package to ignore")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Version"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Optional")," Version of the package to ignore. If no version is set, all versions of the package are ignored.")))),(0,r.kt)("p",null," ex."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-json"},'[\n    {\n        "Id": "NugetDefense",\n        "Version": "1.2.3"\n    },\n    {\n        "Id": "InternalPackage.Invulnerable"\n    }\n]\n')),(0,r.kt)("h2",{id:"log--logs"},"Log / Logs"),(0,r.kt)("p",null,"  The Log configuration section provides options to log the output to a file."),(0,r.kt)("p",null,"  ",(0,r.kt)("inlineCode",{parentName:"p"},"Logs")," accepts an array of file locations instead of a single path."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Field"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Output"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Required")," Path to the log file")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"LogLevel"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Optional")," Log Level to use when logging: ",(0,r.kt)("inlineCode",{parentName:"td"},"Verbose"),", ",(0,r.kt)("inlineCode",{parentName:"td"},"Debug"),", ",(0,r.kt)("inlineCode",{parentName:"td"},"Information"),", ",(0,r.kt)("inlineCode",{parentName:"td"},"Warning"),", ",(0,r.kt)("inlineCode",{parentName:"td"},"Error"),", ",(0,r.kt)("inlineCode",{parentName:"td"},"Fatal"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"RollingInterval"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},"Optional")," Log rotation interval: ",(0,r.kt)("inlineCode",{parentName:"td"},"Infinite"),", ",(0,r.kt)("inlineCode",{parentName:"td"},"Year"),", ",(0,r.kt)("inlineCode",{parentName:"td"},"Month"),",",(0,r.kt)("inlineCode",{parentName:"td"},"Day"),",",(0,r.kt)("inlineCode",{parentName:"td"},"Hour"),",",(0,r.kt)("inlineCode",{parentName:"td"},"Minute"))))),(0,r.kt)("h2",{id:"cachelocation"},"CacheLocation"),(0,r.kt)("p",null,"   Path for the local cache for previously reported known vulnerabilities."),(0,r.kt)("p",null,"   Defaults to: /path/to/SpecialFolder/ApplicationData/.nugetdefense/NugetDefense.sqlite"))}u.isMDXComponent=!0}}]);