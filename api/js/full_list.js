(() => {
	let clicked = null;
	let searchTimeout = null;
	const searchCache = [];
	let caseSensitiveMatch = false;

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
		if (window.getComputedStyle(element).display === "none") return false;
		if (element.parentElement && element.parentElement !== document.body) {
			return isVisible(element.parentElement);
		}
		return true;
	}

	RegExp.escape = (text) => text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");

	function ready(callback) {
		if (document.readyState === "loading") {
			document.addEventListener("DOMContentLoaded", callback, { once: true });
		} else {
			callback();
		}
	}

	function escapeShortcut() {
		document.addEventListener("keydown", (event) => {
			if (event.key === "Escape") {
				window.parent.postMessage("navEscape", "*");
			}
		});
	}

	function clearSearchTimeout() {
		clearTimeout(searchTimeout);
		searchTimeout = null;
	}

	function setClicked(item) {
		queryAll("#full_list li.clicked").forEach((node) => {
			node.classList.remove("clicked");
		});
		clicked = item;
		if (clicked) clicked.classList.add("clicked");
	}

	function pathForItem(item) {
		if (!item?.id || item.id.indexOf("object_") !== 0) return null;
		return item.id.substring("object_".length);
	}

	function enableLinks() {
		queryAll("#full_list li").forEach((item) => {
			const itemRow = item.querySelector(":scope > .item");

			if (!itemRow) return;

			itemRow.addEventListener("click", (event) => {
				let targetLink;
				let url;

				if (
					event.defaultPrevented ||
					event.button !== 0 ||
					event.metaKey ||
					event.ctrlKey ||
					event.shiftKey ||
					event.altKey
				) {
					return true;
				}

				setClicked(item);
				event.stopPropagation();
				targetLink = event.target.closest("a");
				if (!targetLink?.matches(".object_link a")) {
					targetLink = item.querySelector(":scope > .item .object_link a");
				}
				if (!targetLink) return false;

				event.preventDefault();
				url = targetLink.getAttribute("href");
				try {
					url = new URL(url, window.location.href).href;
				} catch (_error) {}
				window.top.postMessage(
					{ action: "navigate", url: url, path: pathForItem(item) },
					"*",
				);
				return false;
			});
		});
	}

	function toggleItem(toggle) {
		const item = toggle.parentElement.parentElement;
		const expanded = item.classList.contains("collapsed");

		item.classList.toggle("collapsed");
		toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
		highlight();
	}

	function enableToggles() {
		queryAll("#full_list a.toggle").forEach((toggle) => {
			toggle.addEventListener("click", (event) => {
				event.stopPropagation();
				event.preventDefault();
				toggleItem(toggle);
			});

			toggle.addEventListener("keypress", (event) => {
				if (event.key !== "Enter") return;
				event.stopPropagation();
				event.preventDefault();
				toggleItem(toggle);
			});
		});
	}

	function populateSearchCache() {
		queryAll("#full_list li .item").forEach((node) => {
			const link = query(".object_link a", node);
			if (!link) return;

			searchCache.push({
				node: node,
				link: link,
				name: link.textContent,
				fullName: link.getAttribute("title").split(" ")[0],
			});
		});
	}

	function enableSearch() {
		const input = query("#search input");
		const fullList = query("#full_list");

		if (!input || !fullList) return;

		function updateSearchResults() {
			if (input.value === "") {
				clearSearch();
			} else {
				performSearch(input.value);
			}
		}

		input.addEventListener("input", updateSearchResults);
		input.addEventListener("change", updateSearchResults);

		fullList.insertAdjacentHTML(
			"afterend",
			"<div id='noresults' role='status' style='display: none'></div>",
		);
	}

	function clearSearch() {
		clearSearchTimeout();
		queryAll("#full_list .found").forEach((node) => {
			node.classList.remove("found");
		});
		query("#full_list").classList.remove("insearch");
		query("#content").classList.remove("insearch");
		if (clicked) {
			let current = clicked.parentElement;
			while (current) {
				if (current.tagName === "LI") current.classList.remove("collapsed");
				if (current.id === "full_list") break;
				current = current.parentElement;
			}
		}
		highlight();
	}

	function performSearch(searchString) {
		clearSearchTimeout();
		query("#full_list").classList.add("insearch");
		query("#content").classList.add("insearch");
		query("#noresults").textContent = "";
		query("#noresults").style.display = "none";
		partialSearch(searchString, 0);
	}

	function partialSearch(searchString, offset) {
		let lastRowClass = "";
		let i;

		for (i = offset; i < Math.min(offset + 50, searchCache.length); i += 1) {
			const item = searchCache[i];
			const searchName =
				searchString.indexOf("::") !== -1 ? item.fullName : item.name;
			const matchRegexp = new RegExp(
				buildMatchString(searchString),
				caseSensitiveMatch ? "" : "i",
			);

			if (!searchName.match(matchRegexp)) {
				item.node.classList.remove("found");
			} else {
				item.node.classList.add("found");
				if (lastRowClass) item.node.classList.remove(lastRowClass);
				item.node.classList.add(lastRowClass === "r1" ? "r2" : "r1");
				lastRowClass = item.node.classList.contains("r1") ? "r1" : "r2";
				item.link.innerHTML = item.name.replace(
					matchRegexp,
					"<strong>$&</strong>",
				);
			}
		}

		if (i === searchCache.length) {
			searchDone();
		} else {
			searchTimeout = setTimeout(() => {
				partialSearch(searchString, i);
			}, 0);
		}
	}

	function searchDone() {
		const found = queryAll("#full_list li").filter(isVisible).length;

		searchTimeout = null;
		highlight();

		if (found === 0) {
			query("#noresults").textContent = "No results were found.";
		} else {
			query("#noresults").textContent = `There are ${found} results.`;
		}
		query("#noresults").style.display = "block";
		query("#content").classList.remove("insearch");
	}

	function buildMatchString(searchString) {
		let regexSearchString;

		caseSensitiveMatch = /[A-Z]/.test(searchString);
		regexSearchString = RegExp.escape(searchString);
		if (caseSensitiveMatch) {
			regexSearchString +=
				"|" +
				searchString
					.split("")
					.map((character) => RegExp.escape(character))
					.join(".+?");
		}
		return regexSearchString;
	}

	function highlight() {
		queryAll("#full_list li")
			.filter(isVisible)
			.forEach((item, index) => {
				item.classList.remove("even");
				item.classList.remove("odd");
				item.classList.add(index % 2 === 0 ? "odd" : "even");
			});
	}

	function isInView(element) {
		const rect = element.getBoundingClientRect();
		const windowHeight =
			window.innerHeight || document.documentElement.clientHeight;
		return rect.left >= 0 && rect.bottom <= windowHeight;
	}

	function expandTo(path) {
		const target = document.getElementById(`object_${path}`);

		if (!target) return;

		setClicked(target);
		target.classList.remove("collapsed");

		let current = target.parentElement;
		while (current && current.id !== "full_list") {
			if (current.tagName === "LI") current.classList.remove("collapsed");
			current = current.parentElement;
		}

		queryAll("a.toggle", target).forEach((toggle) => {
			toggle.setAttribute("aria-expanded", "true");
		});

		current = target.parentElement;
		while (current && current.id !== "full_list") {
			if (current.tagName === "LI") {
				const toggle = current.querySelector(":scope > div > a.toggle");
				if (toggle) toggle.setAttribute("aria-expanded", "true");
			}
			current = current.parentElement;
		}

		highlight();

		if (!isInView(target)) {
			window.scrollTo(
				window.scrollX,
				target.getBoundingClientRect().top + window.scrollY - 250,
			);
		}
	}

	function windowEvents(event) {
		const msg = event.data;
		if (msg.action === "expand") {
			expandTo(msg.path);
		}
		return false;
	}

	window.addEventListener("message", windowEvents, false);

	ready(() => {
		escapeShortcut();
		enableLinks();
		enableToggles();
		populateSearchCache();
		enableSearch();
		highlight();
	});
})();
