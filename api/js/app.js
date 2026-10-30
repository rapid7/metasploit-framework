(() => {
	window.__yardAppState = window.__yardAppState || {
		navigationListenerBound: false,
		navigationChangeBound: false,
		navResizerBound: false,
		searchFrameGlobalsBound: false,
		latestNavigationId: 0,
		loadingIndicatorTimer: null,
		loadingProgressTimer: null,
		loadingProgressHideTimer: null,
		navExpanderTimer: null,
		navExpanderToken: 0,
		currentUrl: window.location.href,
	};
	const appState = window.__yardAppState;
	let safeLocalStorage = {};
	let safeSessionStorage = {};

	try {
		safeLocalStorage = window.localStorage;
	} catch (_error) {}

	try {
		safeSessionStorage = window.sessionStorage;
	} catch (_error) {}

	function query(selector, root) {
		return (root || document).querySelector(selector);
	}

	function queryAll(selector, root) {
		return Array.prototype.slice.call(
			(root || document).querySelectorAll(selector),
		);
	}

	function isVisible(element) {
		if (!element) return false;
		return window.getComputedStyle(element).display !== "none";
	}

	function toggleDisplay(element, visible, displayValue) {
		if (!element) return;
		element.style.display = visible ? displayValue || "" : "none";
	}

	function setMainLoading(loading) {
		const body = document.body;
		const main = query("#main");

		if (body) body.classList.toggle("loading", !!loading);
		if (!main) return;
		main.classList.toggle("loading", !!loading);
		main.setAttribute("aria-busy", loading ? "true" : "false");
	}

	function setLoadingProgress(progress) {
		const indicator = query("#main_progress");

		if (!indicator) return;
		indicator.style.setProperty(
			"--yard-progress",
			`${Math.max(0, Math.min(100, progress))}%`,
		);
	}

	function clearLoadingProgressTimers() {
		clearTimeout(appState.loadingProgressTimer);
		clearTimeout(appState.loadingProgressHideTimer);
		appState.loadingProgressTimer = null;
		appState.loadingProgressHideTimer = null;
	}

	function startLoadingProgress() {
		const startedAt = Date.now();

		clearLoadingProgressTimers();
		setLoadingProgress(0);
		setMainLoading(true);

		function tick() {
			const elapsed = Date.now() - startedAt;
			let progress;

			if (elapsed <= 1000) {
				progress = (elapsed / 1000) * 99;
			} else {
				progress = 99 + Math.min(1, (elapsed - 1000) / 10000);
			}

			setLoadingProgress(progress);

			if (progress < 100) {
				appState.loadingProgressTimer = setTimeout(tick, 50);
			} else {
				appState.loadingProgressTimer = null;
			}
		}

		tick();
	}

	function scheduleMainLoading(navigationId) {
		clearTimeout(appState.loadingIndicatorTimer);
		clearTimeout(appState.loadingProgressHideTimer);
		appState.loadingProgressHideTimer = null;
		appState.loadingIndicatorTimer = setTimeout(() => {
			if (navigationId === appState.latestNavigationId) {
				startLoadingProgress();
			}
			appState.loadingIndicatorTimer = null;
		}, 400);
	}

	function cancelMainLoading() {
		clearTimeout(appState.loadingIndicatorTimer);
		appState.loadingIndicatorTimer = null;
		clearTimeout(appState.loadingProgressTimer);
		appState.loadingProgressTimer = null;
		setLoadingProgress(100);
		appState.loadingProgressHideTimer = setTimeout(() => {
			setMainLoading(false);
			setLoadingProgress(0);
			appState.loadingProgressHideTimer = null;
		}, 120);
	}

	function firstNextMatchingSibling(element, selector) {
		let current = element;
		while (current) {
			current = current.nextElementSibling;
			if (current?.matches(selector)) return current;
		}
		return null;
	}

	function ready(callback) {
		if (document.readyState === "loading") {
			document.addEventListener("DOMContentLoaded", callback, { once: true });
		} else {
			callback();
		}
	}

	function createSourceLinks() {
		queryAll(".method_details_list .source_code").forEach((sourceCode) => {
			const toggleWrapper = document.createElement("span");
			const link = document.createElement("a");

			toggleWrapper.className = "showSource";
			toggleWrapper.appendChild(document.createTextNode("["));
			toggleWrapper.appendChild(link);
			toggleWrapper.appendChild(document.createTextNode("]"));

			link.href = "#";
			link.className = "toggleSource";
			link.textContent = "View source";

			link.addEventListener("click", (event) => {
				event.preventDefault();
				const expanded = isVisible(sourceCode);
				toggleDisplay(sourceCode, !expanded, "table");
				link.textContent = expanded ? "View source" : "Hide source";
			});

			sourceCode.parentNode.insertBefore(toggleWrapper, sourceCode);
		});
	}

	function createDefineLinks() {
		queryAll(".defines").forEach((defines) => {
			const toggleLink = document.createElement("a");
			const summary = defines.parentElement.previousElementSibling;

			toggleLink.href = "#";
			toggleLink.className = "toggleDefines";
			toggleLink.textContent = "more...";
			defines.insertAdjacentText("afterend", " ");
			defines.insertAdjacentElement("afterend", toggleLink);

			toggleLink.addEventListener("click", (event) => {
				event.preventDefault();
				const expanded = toggleLink.dataset.expanded === "true";

				if (!expanded) {
					toggleLink.dataset.height = String(summary.offsetHeight);
					defines.style.display = "inline";
					summary.style.height = `${toggleLink.parentElement.offsetHeight}px`;
					toggleLink.textContent = "(less)";
					toggleLink.dataset.expanded = "true";
				} else {
					defines.style.display = "none";
					if (toggleLink.dataset.height) {
						summary.style.height = `${toggleLink.dataset.height}px`;
					}
					toggleLink.textContent = "more...";
					toggleLink.dataset.expanded = "false";
				}
			});
		});
	}

	function createFullTreeLinks() {
		queryAll(".inheritanceTree").forEach((toggleLink) => {
			const container = toggleLink.parentElement;
			const tree = container.previousElementSibling;

			toggleLink.addEventListener("click", (event) => {
				event.preventDefault();
				const expanded = toggleLink.dataset.expanded === "true";

				if (!expanded) {
					toggleLink.dataset.height = String(tree.offsetHeight);
					container.classList.add("showAll");
					toggleLink.textContent = "(hide)";
					tree.style.height = `${container.offsetHeight}px`;
					toggleLink.dataset.expanded = "true";
				} else {
					container.classList.remove("showAll");
					if (toggleLink.dataset.height) {
						tree.style.height = `${toggleLink.dataset.height}px`;
					}
					toggleLink.textContent = "show all";
					toggleLink.dataset.expanded = "false";
				}
			});
		});
	}

	function resetSearchFrame() {
		const frame = query("#nav");

		if (frame) frame.removeAttribute("style");
		queryAll("#search a").forEach((link) => {
			link.classList.remove("active");
			link.classList.remove("inactive");
		});
		window.focus();
	}

	function toggleSearchFrame(linkElement, link) {
		const frame = query("#nav");

		if (!frame) return;

		queryAll("#search a").forEach((searchLink) => {
			searchLink.classList.remove("active");
			searchLink.classList.add("inactive");
		});

		if (frame.getAttribute("src") === link && isVisible(frame)) {
			frame.style.display = "none";
			queryAll("#search a").forEach((searchLink) => {
				searchLink.classList.remove("active");
				searchLink.classList.remove("inactive");
			});
		} else {
			linkElement.classList.add("active");
			linkElement.classList.remove("inactive");
			if (frame.getAttribute("src") !== link) frame.setAttribute("src", link);
			frame.style.display = "block";
		}
	}

	function searchFrameButtons() {
		queryAll(".full_list_link").forEach((link) => {
			if (link.dataset.yardSearchFrameBound === "true") return;

			link.addEventListener("click", (event) => {
				event.preventDefault();
				toggleSearchFrame(link, link.getAttribute("href"));
			});

			link.dataset.yardSearchFrameBound = "true";
		});

		if (appState.searchFrameGlobalsBound) return;

		window.addEventListener("message", (event) => {
			if (event.data === "navEscape") resetSearchFrame();
		});

		window.addEventListener("resize", () => {
			if (!isVisible(query("#search"))) resetSearchFrame();
		});

		appState.searchFrameGlobalsBound = true;
	}

	function linkSummaries() {
		queryAll(".summary_signature").forEach((signature) => {
			signature.addEventListener("click", (event) => {
				if (event.target.closest("a")) return;
				const link = signature.querySelector("a");
				if (link) document.location = link.getAttribute("href");
			});
		});
	}

	function toggleSummaryCollection(toggleSelector, listSelector, cloneBuilder) {
		queryAll(toggleSelector).forEach((toggleLink) => {
			toggleLink.addEventListener("click", (event) => {
				event.preventDefault();
				safeLocalStorage.summaryCollapsed = toggleLink.textContent;

				queryAll(toggleSelector).forEach((link) => {
					link.textContent =
						link.textContent === "collapse" ? "expand" : "collapse";

					const container = link.parentElement.parentElement;
					const next = firstNextMatchingSibling(container, listSelector);

					if (!next) return;

					if (next.classList.contains("compact")) {
						const fullList = firstNextMatchingSibling(next, listSelector);
						toggleDisplay(next, !isVisible(next));
						toggleDisplay(fullList, !isVisible(fullList));
					} else {
						const compactList = cloneBuilder(next.cloneNode(true));
						next.parentNode.insertBefore(compactList, next);
						toggleDisplay(next, false);
					}
				});
			});
		});
	}

	function buildCompactSummary(list) {
		list.className = "summary compact";

		queryAll(".summary_desc, .note", list).forEach((node) => {
			node.remove();
		});

		queryAll("a", list).forEach((link) => {
			const strong = link.querySelector("strong");
			if (strong) link.innerHTML = strong.innerHTML;
			if (link.parentElement) link.parentElement.outerHTML = link.outerHTML;
		});

		return list;
	}

	function buildCompactConstants(list) {
		list.className = "constants compact";

		queryAll("dt", list).forEach((node) => {
			const deprecated = !!node.querySelector(".deprecated");
			node.classList.add("summary_signature");
			node.textContent = node.textContent.split("=")[0];
			if (deprecated) node.classList.add("deprecated");
		});

		queryAll("pre.code", list).forEach((pre) => {
			const dtElement = pre.parentElement.previousElementSibling;
			let tooltip = pre.textContent;
			if (dtElement.classList.contains("deprecated")) {
				tooltip = `Deprecated. ${tooltip}`;
			}
			dtElement.setAttribute("title", tooltip);
		});

		queryAll(".docstring, .tags, dd", list).forEach((node) => {
			node.remove();
		});

		return list;
	}

	function summaryToggle() {
		toggleSummaryCollection(
			".summary_toggle",
			"ul.summary",
			buildCompactSummary,
		);

		if (safeLocalStorage.summaryCollapsed === "collapse") {
			const toggle = query(".summary_toggle");
			if (toggle) toggle.click();
		} else {
			safeLocalStorage.summaryCollapsed = "expand";
		}
	}

	function constantSummaryToggle() {
		toggleSummaryCollection(
			".constants_summary_toggle",
			"dl.constants",
			buildCompactConstants,
		);

		if (safeLocalStorage.summaryCollapsed === "collapse") {
			const toggle = query(".constants_summary_toggle");
			if (toggle) toggle.click();
		} else {
			safeLocalStorage.summaryCollapsed = "expand";
		}
	}

	function generateTOC() {
		const fileContents = query("#filecontents");
		const content = query("#content");

		if (!fileContents || !content) return;
		if (query("#toc", content)) return;

		const topLevel = document.createElement("ol");
		let currentList = topLevel;
		let currentItem;
		let counter = 0;
		const headings = ["h2", "h3", "h4", "h5", "h6"];
		let hasEntries = false;

		topLevel.className = "top";

		if (queryAll("#filecontents h1").length > 1) headings.unshift("h1");

		const selectors = headings.map((tagName) => `#filecontents ${tagName}`);

		let lastLevel = parseInt(headings[0].substring(1), 10);

		queryAll(selectors.join(", ")).forEach((heading) => {
			let level;

			if (heading.closest(".method_details .docstring")) return;
			if (heading.id === "filecontents") return;

			hasEntries = true;
			level = parseInt(heading.tagName.substring(1), 10);

			if (!heading.id) {
				let proposedId = heading.getAttribute("toc-id");
				if (!proposedId) {
					proposedId = heading.textContent.replace(/[^a-z0-9-]/gi, "_");
					if (query(`#${proposedId}`)) {
						proposedId += counter;
						counter += 1;
					}
				}
				heading.id = proposedId;
			}

			if (level > lastLevel) {
				while (level > lastLevel) {
					if (!currentItem) {
						currentItem = document.createElement("li");
						currentList.appendChild(currentItem);
					}
					const nestedList = document.createElement("ol");
					currentItem.appendChild(nestedList);
					currentList = nestedList;
					currentItem = null;
					lastLevel += 1;
				}
			} else if (level < lastLevel) {
				while (level < lastLevel && currentList.parentElement) {
					currentList = currentList.parentElement.parentElement;
					lastLevel -= 1;
				}
			}

			const title = heading.getAttribute("toc-title") || heading.textContent;
			const item = document.createElement("li");
			item.innerHTML = `<a href="#${heading.id}">${title}</a>`;
			currentList.appendChild(item);
			currentItem = item;
		});

		if (!hasEntries) return;

		const toc = document.createElement("div");
		toc.id = "toc";
		toc.innerHTML =
			'<p class="title hide_toc"><a href="#"><strong>Table of Contents</strong></a></p>';
		content.insertBefore(toc, content.firstChild);
		toc.appendChild(topLevel);

		const hideLink = query("#toc .hide_toc");
		if (hideLink) {
			hideLink.addEventListener("click", (event) => {
				event.preventDefault();
				const list = query("#toc .top");
				const hidden = query("#toc").classList.toggle("hidden");
				toggleDisplay(list, !hidden);
				queryAll("#toc .title small").forEach((node) => {
					toggleDisplay(node, hidden);
				});
			});
		}
	}

	function navResizer() {
		const resizer = document.getElementById("resizer");

		if (!resizer) return;

		if (!appState.navResizerBound) {
			resizer.addEventListener(
				"pointerdown",
				(event) => {
					resizer.setPointerCapture(event.pointerId);
					event.preventDefault();
					event.stopPropagation();
				},
				false,
			);
			resizer.addEventListener(
				"pointerup",
				(event) => {
					resizer.releasePointerCapture(event.pointerId);
					event.preventDefault();
					event.stopPropagation();
				},
				false,
			);
			resizer.addEventListener(
				"pointermove",
				(event) => {
					if ((event.buttons & 1) === 0) return;

					safeSessionStorage.navWidth = String(event.pageX);
					queryAll(".nav_wrap").forEach((node) => {
						node.style.width = `${Math.max(200, event.pageX)}px`;
					});
					event.preventDefault();
					event.stopPropagation();
				},
				false,
			);

			appState.navResizerBound = true;
		}

		if (safeSessionStorage.navWidth) {
			queryAll(".nav_wrap").forEach((node) => {
				node.style.width = `${Math.max(200, parseInt(safeSessionStorage.navWidth, 10))}px`;
			});
		}
	}

	function navExpander(enabled) {
		if (enabled === false) return;
		if (typeof pathId === "undefined") return;

		const frame = document.getElementById("nav");
		const token = ++appState.navExpanderToken;

		function postMessage() {
			if (token !== appState.navExpanderToken) return;
			expandNavPath(pathId);
		}

		clearTimeout(appState.navExpanderTimer);
		if (frame) frame.addEventListener("load", postMessage, { once: true });
		appState.navExpanderTimer = setTimeout(postMessage, 50);
	}

	function expandNavPath(path) {
		const frame = document.getElementById("nav");

		if (path == null || !frame || !frame.contentWindow) return;
		frame.contentWindow.postMessage({ action: "expand", path: path }, "*");
	}

	function focusHashTarget(hashOverride) {
		const hash =
			typeof hashOverride === "string" ? hashOverride : window.location.hash;
		if (!hash) return false;

		const targetId = hash.slice(1);
		let decodedTargetId = targetId;

		try {
			decodedTargetId = decodeURIComponent(targetId);
		} catch (_error) {}

		const target =
			document.getElementById(decodedTargetId) ||
			document.getElementById(targetId);

		if (!target) return false;

		target.scrollIntoView();
		return true;
	}

	function resetMainScroll() {
		const main = query("#main");

		if (main) {
			main.scrollTop = 0;
			main.scrollLeft = 0;
		}
		window.scrollTo(0, 0);
	}

	function mainFocus() {
		if (!focusHashTarget()) {
			resetMainScroll();
		}
		setTimeout(() => {
			const main = query("#main");
			if (main) main.focus();
		}, 10);
	}

	function navigationChange() {
		if (appState.navigationChangeBound) return;

		window.addEventListener("popstate", () => {
			navigateTo(window.location.href, {
				pushHistory: false,
				syncNav: true,
			});
		});
		appState.navigationChangeBound = true;
	}

	function sameDocumentUrl(left, right) {
		const leftUrl = new URL(left, window.location.href);
		const rightUrl = new URL(right, window.location.href);

		return (
			leftUrl.origin === rightUrl.origin &&
			leftUrl.pathname === rightUrl.pathname &&
			leftUrl.search === rightUrl.search
		);
	}

	function contentPageUrl(url) {
		const pageUrl = new URL(url, window.location.href);

		pageUrl.hash = "";
		return pageUrl.href;
	}

	function updatePageState(doc, pageWindow) {
		const nextMain = doc.querySelector("#main");
		const currentMain = query("#main");
		const currentClassListLink = query("#class_list_link");
		const currentClassListClassName = currentClassListLink
			? currentClassListLink.className
			: null;

		if (!nextMain || !currentMain) return false;

		currentMain.innerHTML = nextMain.innerHTML;
		document.title = doc.title;

		if (currentClassListClassName && query("#class_list_link")) {
			query("#class_list_link").className = currentClassListClassName;
		}

		if (pageWindow && typeof pageWindow.pathId !== "undefined") {
			pathId = pageWindow.pathId;
		}

		if (pageWindow && typeof pageWindow.relpath !== "undefined") {
			relpath = pageWindow.relpath;
		}

		return true;
	}

	function pageLoaderFrame() {
		let frame = query("#page_loader");

		if (frame) return frame;

		frame = document.createElement("iframe");
		frame.id = "page_loader";
		frame.setAttribute("aria-hidden", "true");
		frame.setAttribute("tabindex", "-1");
		frame.style.display = "none";
		document.body.appendChild(frame);
		return frame;
	}

	function completeNavigation(url, options, pageWindow, pageDocument) {
		const targetUrl = new URL(url, window.location.href);

		if (!updatePageState(pageDocument, pageWindow)) return false;

		window.__app({ rehydrateNav: false });

		if (options.syncNav && typeof pathId !== "undefined") {
			expandNavPath(pathId);
		}

		if (targetUrl.hash) {
			focusHashTarget(targetUrl.hash);
		} else {
			resetMainScroll();
		}

		if (options.pushHistory) {
			history.pushState({}, document.title, targetUrl.href);
		}
		appState.currentUrl = targetUrl.href;

		return true;
	}

	function navigateTo(url, options) {
		const navigationOptions = Object.assign(
			{ pushHistory: true, syncNav: false },
			options || {},
		);
		const navigationId = ++appState.latestNavigationId;
		const loader = pageLoaderFrame();
		const resolvedUrl = new URL(url, window.location.href).href;
		const loaderUrl = contentPageUrl(resolvedUrl);

		if (sameDocumentUrl(appState.currentUrl, resolvedUrl)) {
			const resolvedTargetUrl = new URL(resolvedUrl);

			if (navigationOptions.pushHistory) {
				history.pushState({}, document.title, resolvedUrl);
			}
			appState.currentUrl = resolvedUrl;
			if (resolvedTargetUrl.hash) {
				focusHashTarget(resolvedTargetUrl.hash);
			} else {
				resetMainScroll();
			}
			return;
		}

		scheduleMainLoading(navigationId);

		loader.onload = () => {
			let pageWindow;
			let pageDocument;
			let completed = false;

			if (navigationId !== appState.latestNavigationId) return;

			try {
				pageWindow = loader.contentWindow;
				pageDocument = loader.contentDocument || pageWindow.document;
				completed = completeNavigation(
					resolvedUrl,
					navigationOptions,
					pageWindow,
					pageDocument,
				);
			} catch (_error) {
				window.location.href = resolvedUrl;
				return;
			} finally {
				if (navigationId === appState.latestNavigationId) {
					cancelMainLoading();
				}
				if (completed) {
					loader.onload = null;
					loader.removeAttribute("src");
				}
			}
		};

		loader.src = loaderUrl;
	}

	window.__app = (options) => {
		const appOptions = options || {};
		ready(() => {
			navResizer();
			navExpander(appOptions.rehydrateNav !== false);
			createSourceLinks();
			createDefineLinks();
			createFullTreeLinks();
			searchFrameButtons();
			linkSummaries();
			summaryToggle();
			constantSummaryToggle();
			generateTOC();
			mainFocus();
			navigationChange();
		});
	};

	window.__app();

	if (!appState.navigationListenerBound) {
		window.addEventListener(
			"message",
			(event) => {
				if (!event.data || event.data.action !== "navigate") return;

				navigateTo(event.data.url, {
					pushHistory: true,
					syncNav: false,
				});
			},
			false,
		);

		appState.navigationListenerBound = true;
	}
})();
