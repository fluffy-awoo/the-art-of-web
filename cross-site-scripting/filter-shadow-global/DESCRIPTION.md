Real apps often try to stop XSS by filtering the input before it ever reaches the page. A common naive way to do this is a blocklist: the server scans your input for dangerous-looking patterns and rejects it if it finds one. This series of challenges is about getting a payload past that kind of filter.

The weakness of a blocklist is that it can only block what its authors thought to block. There are many ways to reach the same result, so if the filter misses even one, you are through.

In this challenge the following elements are banned:

- `script`, `img`, `svg`, `iframe`, `input`, `object`, `embed`
- `video`, `audio`, `source`, `track`
- `html`, `body`, `frame`, `frameset`, `details`, `dialog`, `marquee`
- `style`, `link`, `template`
- `applet`, `base`, `component`, `geolocation`, `math`, `meta`

The following event handlers are also banned:

- `onafterprint`
- `onanimationcancel`
- `onanimationend`
- `onanimationiteration`
- `onanimationstart`
- `onauxclick`
- `onbeforecopy`
- `onbeforecut`
- `onbeforeinput`
- `onbeforematch`
- `onbeforepaste`
- `onbeforeprint`
- `onbeforetoggle`
- `onbeforeunload`
- `onbegin`
- `onblur`
- `onbounce`
- `oncancel`
- `oncanplay`
- `oncanplaythrough`
- `onchange`
- `onclick`
- `onclose`
- `oncommand`
- `oncontentvisibilityautostatechange`
- `oncontextmenu`
- `oncopy`
- `oncuechange`
- `oncut`
- `ondevicemotion`
- `ondeviceorientation`
- `ondeviceorientationabsolute`
- `ondblclick`
- `ondrag`
- `ondragend`
- `ondragenter`
- `ondragexit`
- `ondragleave`
- `ondragover`
- `ondragstart`
- `ondrop`
- `ondurationchange`
- `onend`
- `onended`
- `onerror`
- `onfinish`
- `onfocus`
- `onfocusin`
- `onfocusout`
- `onformdata`
- `onfullscreenchange`
- `ongesturechange`
- `ongestureend`
- `ongesturestart`
- `ongotpointercapture`
- `onhashchange`
- `oninput`
- `oninvalid`
- `onkeydown`
- `onkeypress`
- `onkeyup`
- `onload`
- `onloadeddata`
- `onloadend`
- `onloadedmetadata`
- `onloadstart`
- `onlocation`
- `onlostpointercapture`
- `onmessage`
- `onmousedown`
- `onmouseenter`
- `onmouseleave`
- `onmousemove`
- `onmouseout`
- `onmouseover`
- `onmouseup`
- `onmousewheel`
- `onmozfullscreenchange`
- `onpagehide`
- `onpagereveal`
- `onpageshow`
- `onpageswap`
- `onpaste`
- `onpause`
- `onplay`
- `onplaying`
- `onpointercancel`
- `onpointerdown`
- `onpointerenter`
- `onpointerleave`
- `onpointermove`
- `onpointerout`
- `onpointerover`
- `onpointerrawupdate`
- `onpointerup`
- `onpopstate`
- `onprogress`
- `onpromptaction`
- `onpromptdismiss`
- `onratechange`
- `onrepeat`
- `onreset`
- `onresize`
- `onscrollend`
- `onscrollsnapchange`
- `onscrollsnapchanging`
- `onsearch`
- `onsecuritypolicyviolation`
- `onseeked`
- `onseeking`
- `onselect`
- `onselectionchange`
- `onselectstart`
- `onshow`
- `onslotchange`
- `onstart`
- `onsubmit`
- `onsuspend`
- `ontimeupdate`
- `ontoggle`
- `ontouchcancel`
- `ontouchend`
- `ontouchmove`
- `ontouchstart`
- `ontransitioncancel`
- `ontransitionend`
- `ontransitionrun`
- `ontransitionstart`
- `onunhandledrejection`
- `onunload`
- `onvalidationstatuschange`
- `onvolumechange`
- `onwaiting`
- `onwebkitanimationend`
- `onwebkitanimationiteration`
- `onwebkitanimationstart`
- `onwebkitfullscreenchange`
- `onwebkitmouseforcechanged`
- `onwebkitmouseforcedown`
- `onwebkitmouseforceup`
- `onwebkitmouseforcewillbegin`
- `onwebkitneedkey`
- `onwebkitplaybacktargetavailabilitychanged`
- `onwebkitpresentationmodechanged`
- `onwebkittransitionend`
- `onwebkitwillrevealbottom`
- `onwheel`

`autofocus` is also banned.

The following attributes are also banned:

- `style`, `animation`, `keyframes`, `content-visibility`
- `transition`, `transform`

The following shadow DOM primitives are also banned:

- `shadow`, `slot`

The following APIs and globals are also banned:

- `fetch`, `XMLHttpRequest`, `sendBeacon`
- `location`, `open()`, `assign()`, `replace()`, `pushState`, `replaceState`
- `submit`, `requestSubmit`, `click`, `write`, `writeln`
- `createElement`, `createElementNS`, `adoptNode`, `importNode`, `cloneNode`
- `append`, `appendChild`, `prepend`, `before`, `after`, `insertBefore`
- `insertAdjacentHTML`, `insertAdjacentText`, `insertAdjacentElement`
- `replaceChildren`, `replaceChild`, `replaceWith`, `remove`, `removeChild`
- `innerHTML`, `outerHTML`, `innerText`, `outerText`, `textContent`
- `setAttribute`, `setAttributeNS`, `removeAttribute`, `removeAttributeNS`, `toggleAttribute`
- `querySelector`, `querySelectorAll`, `getElementById`, `getElementsByTagName`, `getElementsByClassName`, `getElementsByName`
- `href`, `src`, `action`, `formAction`, `srcdoc`
- `cookie`, `cookieStore`, `localStorage`, `sessionStorage`
- `FormData`, `URL`, `URLSearchParams`, `Request`, `Headers`, `Response`
- `media`, `Image`, `Audio`, `Video`, `Track`, `Source`, `Bitmap`, `Canvas`, `Blob`, `File`
- `navigator`, `geolocation`, `navigation`, `postMessage`, `document`, `window`, `globalThis`, `global`, `self`, `this`, `top`, `parent`, `frames`, `form`, `element`, `constructor`
- `eval`, `Function`, `setTimeout`, `setInterval`, `import()`
- `alert()`, `confirm()`, `prompt()`, `print()`

The `javascript:` URL scheme is banned, including variants containing ASCII whitespace. Nested percent encoding, HTML entities, JavaScript Unicode, hexadecimal, octal, simple, identity, and line-continuation escapes, and null bytes are normalized before these checks.

A Content Security Policy is also applied: `style-src 'nonce-{random}'; style-src-attr 'none'`

Find a way to run your payload without using any of them.
