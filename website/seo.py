#!/usr/bin/env python3
"""SEO/GEO helpers for the Vericexa website: per-page meta tags (canonical,
Open Graph, Twitter Card), JSON-LD structured data, sitemap.xml and
robots.txt.

Pure functions of the page data content.py already centralizes - no new
brand/product facts are introduced here, only their structured-data and
meta-tag encoding. Standard library only.
"""
from __future__ import annotations

import json
from html import escape
from typing import Any, Dict, List, Optional, Tuple

import content as c

# Deterministic, manually-bumped alongside BUILD_VERSION in build_site.py -
# never datetime.now(), so the generator stays a pure function of its inputs
# (same discipline the rest of this build already follows).
SITE_LAST_UPDATED = "2026-09-19"


def page_url(base_url: str, filename: str) -> str:
    if filename == "index.html":
        return base_url.rstrip("/") + "/"
    return base_url.rstrip("/") + "/" + filename


def render_head_meta(page_name: str, base_url: str) -> str:
    """<title>, meta description, canonical, Open Graph and Twitter Card tags."""
    title = c.PAGE_TITLES[page_name]
    description = c.PAGE_DESCRIPTIONS[page_name]
    url = page_url(base_url, page_name)
    return (
        "<title>%s</title>\n"
        "<meta name=\"description\" content=\"%s\">\n"
        "<link rel=\"canonical\" href=\"%s\">\n"
        "<meta property=\"og:type\" content=\"website\">\n"
        "<meta property=\"og:site_name\" content=\"%s\">\n"
        "<meta property=\"og:title\" content=\"%s\">\n"
        "<meta property=\"og:description\" content=\"%s\">\n"
        "<meta property=\"og:url\" content=\"%s\">\n"
        "<meta name=\"twitter:card\" content=\"summary\">\n"
        "<meta name=\"twitter:title\" content=\"%s\">\n"
        "<meta name=\"twitter:description\" content=\"%s\">\n"
    ) % (
        escape(title), escape(description), escape(url),
        escape(c.BRAND_NAME), escape(title), escape(description), escape(url),
        escape(title), escape(description),
    )


def _jsonld_script(data: Dict[str, Any]) -> str:
    # separators=(",", ":") keeps output compact; ensure_ascii=False since the
    # site is English-only ASCII copy anyway. </script> can never appear in
    # this generator's own structured data (no user-controlled input flows
    # into it), but the replace is defense in depth for the embedding context.
    payload = json.dumps(data, ensure_ascii=False).replace("</script>", "<\\/script>")
    return "<script type=\"application/ld+json\">%s</script>\n" % payload


def organization_jsonld(base_url: str) -> str:
    return _jsonld_script({
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": c.BRAND_NAME,
        "url": base_url.rstrip("/") + "/",
        "description": c.POSITIONING,
        "logo": base_url.rstrip("/") + "/favicon.svg",
    })


def website_jsonld(base_url: str) -> str:
    return _jsonld_script({
        "@context": "https://schema.org",
        "@type": "WebSite",
        "name": c.BRAND_NAME,
        "url": base_url.rstrip("/") + "/",
        "description": c.POSITIONING,
    })


def software_application_jsonld(base_url: str) -> str:
    # Deliberately no "offers"/price field: pricing is unpublished
    # (content.PRICING_PUBLISHED is False) and structured data must never
    # assert a number the site itself refuses to show (same discipline as
    # the pricing page and the commercial-claims sweep).
    return _jsonld_script({
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": c.BRAND_NAME,
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Any",
        "description": c.POSITIONING,
        "url": base_url.rstrip("/") + "/",
    })


def breadcrumb_jsonld(base_url: str, page_name: str) -> str:
    label = dict(c.ALL_PAGES)[page_name]
    items = [{"@type": "ListItem", "position": 1, "name": "Home", "item": page_url(base_url, "index.html")}]
    if page_name != "index.html":
        items.append({"@type": "ListItem", "position": 2, "name": label, "item": page_url(base_url, page_name)})
    return _jsonld_script({"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": items})


def faq_jsonld(items: List[Tuple[str, str]]) -> str:
    return _jsonld_script({
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [
            {
                "@type": "Question",
                "name": question,
                "acceptedAnswer": {"@type": "Answer", "text": answer},
            }
            for question, answer in items
        ],
    })


def render_sitemap_xml(base_url: str, pages: List[str]) -> str:
    entries = []
    for name in pages:
        entries.append(
            "  <url>\n    <loc>%s</loc>\n    <lastmod>%s</lastmod>\n  </url>"
            % (escape(page_url(base_url, name)), SITE_LAST_UPDATED)
        )
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
        + "\n".join(entries)
        + "\n</urlset>\n"
    )


def render_robots_txt(base_url: str) -> str:
    return (
        "User-agent: *\n"
        "Allow: /\n"
        "Sitemap: %s\n"
    ) % (base_url.rstrip("/") + "/sitemap.xml")
