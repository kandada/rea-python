# Disclaimer

rea-mcp is an **unofficial, independent Python port** of [morluto/rea](https://github.com/morluto/rea). It is not affiliated with, sponsored by, or endorsed by the original authors. The original REA project is a TypeScript implementation. This document explains intended use, user responsibilities, and support boundaries; it is modeled on REA's responsible-use guidance.

## Responsible use

rea-mcp is built for lawful analysis: security research, malware and incident analysis, vulnerability research and coordinated disclosure, CTFs and education, interoperability, software preservation, and debugging or auditing software you own or are authorized to examine.

The project does not support, and will not help with:

- circumventing DRM, license checks, anti-cheat systems or other technical protection measures;
- developing game cheats or tampering with online services;
- bypassing authentication, bot protection or access controls on systems you are not authorized to test;
- copying proprietary software or reproducing its protected code and assets;
- evading the usage policies or safety measures of AI model providers;
- reselling or sharing AI accounts or API access.

You are responsible for obtaining any required authorization and for complying with applicable laws, license agreements and terms of service. Reverse engineering may be restricted in your jurisdiction or by the license of the software you analyze.

## User responsibility

Do not use rea-mcp for unauthorized access or exploitation, credential theft, malicious deployment of malware, unlawful collection or disclosure of data, unauthorized service disruption, or unlawful circumvention of access controls or licensing restrictions. Legitimate security research and malware analysis must remain within the rights and permissions applicable to the work.

You are responsible for your use of rea-mcp, including commands, configurations, scripts, and actions you direct an AI agent to perform. Establish the legal authority and scope required for the targets, accounts, devices, software, data, and operations involved. Comply with applicable laws, contracts, intellectual-property rights, privacy obligations, and tool licenses.

## Runtime, network, and device operations

Some workflows execute or observe programs, attach to runtime or browser endpoints, capture network traffic, interact with applications, or operate on connected devices. These actions can affect application state, files, accounts, devices, and services. Authorization to inspect an artifact does not necessarily authorize execution, interception, device changes, or interaction with another party's system.

Review the operations you request, including agent-generated plans and scripts, and use an appropriate environment for untrusted targets. You are responsible for protecting credentials, personal data, captured traffic, and investigation artifacts.

## Analysis results and generated output

Decompilation, reconstruction, heuristics, and AI-assisted analysis may be incomplete or incorrect. Results do not guarantee accuracy, completeness, security, compatibility, or legal compliance. Review the underlying evidence and verify consequential conclusions before relying on them. Obtaining source-like output or an analysis report does not grant rights to the original program, its data, or the generated output.

## Third-party tools and licenses

Third-party components and external analysis tools retain their own licenses, copyright notices, and usage conditions. rea-mcp does not bundle or install these engines; you must legally obtain and be authorized to use them. This includes (non-exhaustively) Ghidra, Hopper, IDA Pro / Hex-Rays, JEB, Rizin/radare2, objdump/binutils, WABT, mitmproxy, Wireshark/tshark, Binwalk, Frida, playwright, pwntools/pwndbg, and adb. rea-mcp grants no commercial-tool license, key, or activation entitlement. Cracked copies, stolen keys, unauthorized key sharing, and bypassing license restrictions are not authorized. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Disclaimer of warranty

rea-mcp is provided **AS IS**, without express or implied warranties, including merchantability, fitness for a particular purpose, and noninfringement, as set out in the [MIT License](LICENSE). You assume the risks of using the software and deciding whether it is suitable for your task.

## Limitation of liability

The warranty and liability provisions of the [MIT License](LICENSE) govern rea-mcp's authors and copyright holders, subject to applicable law. That license disclaims liability for claims, damages, and other liability arising from or in connection with the software or its use.

## Disclaimer of endorsement

References to third-party projects, products, services, and trademarks (including REA and morluto/rea) identify their work and rea-mcp's integrations. Credits do not imply affiliation, sponsorship, approval, or endorsement by the named parties. Redistribution, bundling, or hosting by a third party does not by itself imply affiliation with or endorsement by the rea-mcp project.

## Relationship to software licenses

This document explains intended use, user responsibilities, and community support boundaries. It does not amend the MIT license, impose additional copyright-license conditions, replace upstream licenses, or grant rights to third-party software or targets.

## Versions and distribution channels

The project's position on lawful use and non-endorsement covers all rea-mcp versions, distribution forms, and platforms, including Git commits, PyPI releases, source checkouts, archives, and redistributed copies. Each copy remains subject to the licenses accompanying that copy.
