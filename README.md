> # Vulnerabilities-of-the-nightcraft.ir-server-Minecraft-server-

**------------------ nihgtcraft.ir ------------------

> ( / ) The server does not have a CSP
> ( /cgi-bin/.cobalt/alert/service.cgi ) Cobalt RaQ 4 administration CGI is vulnerable to Cross Site Scripting (XSS)
> ( /user.php ) Post Nuke 0.7.2.3-Phoenix is vulnerable to Cross Site Scripting (XSS)
> ( /phpimageview.php ) PHP Image View 1.0 is vulnerable to Cross Site Scripting (XSS)
> ( /modules.php ) Post Nuke 0.7.2.3-Phoenix is vulnerable to Cross Site Scripting (XSS)
> ( /members.asp ) Web Wiz Forums ver. 7.01 and below is vulnerable to Cross Site Scripting (XSS)
> ( /forum_members.asp ) Web Wiz Forums ver. 7.01 and below is vulnerable to Cross Site Scripting (XSS)
> ( /sitemap.xml ) This gives a nice listing of the site content
> ( /whnqw.xml ) Coccoon from Apache-XML project reveals file system path in error messages
> ( /wp-app.log ) Wordpress' wp-app.log may leak application/system details

--------------- MIME Type Confusion ---------------

= Fingerprint web server

> ( / ) {"name": "Nginx", "versions": ["1.18.0"], "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "categories": ["Web servers", "Reverse proxies"], "groups": ["Servers"]}

= Clickjacking Protection

> ( / ) X-Frame-Options is not set

= MIME Type Confusion

> ( / ) X-Content-Type-Options is not set

--------------- Vulnerable software ---------------

> ( / ) nginx CVE-2022-41741: NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription before versions R2 P1 and R1 P1, and NGINX Plus before versions R27 P1 and R26 P1 have a vulnerability in the module ngx_http_mp4_module that might allow a local attacker to corrupt NGINX worker memory, resulting in its termination or potential other impact using a specially crafted audio or video file. The issue affects only NGINX products that are built with the ngx_http_mp4_module, when the mp4 directive is used in the configuration file. Further, the attack is possible only if an attacker can trigger processing of a specially crafted audio or video file with the module ngx_http_mp4_module
> ( / ) nginx CVE-2022-41742: NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription before versions R2 P1 and R1 P1, and NGINX Plus before versions R27 P1 and R26 P1 have a vulnerability in the module ngx_http_mp4_module that might allow a local attacker to cause a worker process crash, or might result in worker process memory disclosure by using a specially crafted audio or video file. The issue affects only NGINX products that are built with the module ngx_http_mp4_module, when the mp4 directive is used in the configuration file. Further, the attack is possible only if an attacker can trigger processing of a specially crafted audio or video file with the module ngx_http_mp4_module
> ( / ) nginx CVE-2023-44487: The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023
> ( / ) nginx CVE-2021-23017: A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory overwrite, resulting in worker process crash or potential other impact
> ( / ) nginx CVE-2021-3618: ALPACA is an application layer protocol content confusion attack, exploiting TLS servers implementing different protocols but using compatible certificates, such as multi-domain or wildcard certificates. A MiTM attacker having access to victim's traffic at the TCP/IP layer can redirect traffic from one subdomain to another, resulting in a valid TLS session. This breaks the authentication of TLS and cross-protocol attacks may be possible where the behavior of one protocol service may compromise the other at the application layer

----------- Fingerprint web technology ------------

> ( / ) {"name": "Cart Functionality", "versions": [], "cpe": "", "categories": ["Ecommerce"], "groups": ["Sales"]}
> ( / ) {"name": "HSTS", "versions": [], "cpe": "", "categories": ["Security"], "groups": ["Security"]}
> ( / ) {"name": "Next.js", "versions": [], "cpe": "cpe:2.3:a:zeit:next.js:*:*:*:*:*:*:*:*", "categories": ["JavaScript frameworks", "Web frameworks"], "groups": ["Web development"]}
> ( / ) {"name": "Nginx", "versions": ["1.18.0"], "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "categories": ["Web servers", "Reverse proxies"], "groups": ["Servers"]}
> ( / ) {"name": "Node.js", "versions": [], "cpe": "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", "categories": ["Programming languages"], "groups": ["Web development"]}
> ( / ) {"name": "Open Graph", "versions": [], "cpe": "", "categories": ["Miscellaneous"], "groups": ["Other"]}
> ( / ) {"name": "Priority Hints", "versions": [], "cpe": "", "categories": ["Performance"], "groups": ["Servers"]}
> ( / ) {"name": "Radix UI", "versions": [], "cpe": "", "categories": ["UI frameworks"], "groups": ["Web development"]}
> ( / ) {"name": "React", "versions": [], "cpe": "cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*", "categories": ["JavaScript frameworks"], "groups": ["Web development"]}
> ( / ) {"name": "Ubuntu", "versions": [], "cpe": "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*", "categories": ["Operating systems"], "groups": ["Servers"]}
> ( / ) {"name": "Webpack", "versions": [], "cpe": "", "categories": ["Miscellaneous"], "groups": ["Other"]}

------------------ HTTP Methods ------------------

> ( / ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/: OPTIONS (405)
> ( /_next/image ) Possible interesting methods (using heuristics) on https://nightcraft.ir/_next/image: CONNECT (502) DELETE (404) PATCH (404) POST (404) PUT (404)
> ( /_next/static/chunks/277-34ac9409e9b139a7.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/277-34ac9409e9b139a7.js: OPTIONS (400)
> ( /_next/static/chunks/454-f81709ba79b5b959.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/454-f81709ba79b5b959.js: OPTIONS (400)
> ( /_next/static/chunks/49-ab243d419c87a989.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/49-ab243d419c87a989.js: OPTIONS (400)
> ( /_next/static/chunks/4bd1b696-3abbb802821b0a68.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/4bd1b696-3abbb802821b0a68.js: OPTIONS (400)
> ( /_next/static/chunks/65-717f04ec7eacf5eb.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/65-717f04ec7eacf5eb.js: OPTIONS (400)
> ( /_next/static/chunks/683-ba2ebe5c0ab33952.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/683-ba2ebe5c0ab33952.js: OPTIONS (400)
> ( /_next/static/chunks/833-3d628b1e7e79751e.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/833-3d628b1e7e79751e.js: OPTIONS (400)
> ( /_next/static/chunks/874-476808868ec6108b.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/874-476808868ec6108b.js: OPTIONS (400)
> ( /_next/static/chunks/8e1d74a4-6e684444c9722a76.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/8e1d74a4-6e684444c9722a76.js: OPTIONS (400)
> ( /_next/static/chunks/912-f1b126bc445ca78b.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/912-f1b126bc445ca78b.js: OPTIONS (400)
> ( /_next/static/chunks/app/info/page-0af7368520552386.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/app/info/page-0af7368520552386.js: OPTIONS (400)
> ( /_next/static/chunks/app/layout-758c9e21134a1697.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/app/layout-758c9e21134a1697.js: OPTIONS (400)
> ( /_next/static/chunks/app/page-5acf2f45a5269798.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/app/page-5acf2f45a5269798.js: OPTIONS (400)
> ( /_next/static/chunks/app/shop/page-bd64cef2672144e3.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/app/shop/page-bd64cef2672144e3.js: OPTIONS (400)
> ( /_next/static/chunks/main-app-4edecdd05708a69b.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/main-app-4edecdd05708a69b.js: OPTIONS (400)
> ( /_next/static/chunks/polyfills-42372ed130431b0a.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/polyfills-42372ed130431b0a.js: OPTIONS (400)
> ( /_next/static/chunks/webpack-c0085bb0c7f48842.js ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/_next/static/chunks/webpack-c0085bb0c7f48842.js: OPTIONS (400)
> ( /info ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/info: OPTIONS (405)
> ( /shop ) Possible interesting methods (using OPTIONS) on https://nightcraft.ir/shop: OPTIONS (405)


--- Creator: t.me/GKSVGk --- Channel: @dev_2yt_code_c**


