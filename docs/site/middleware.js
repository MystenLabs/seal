// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

const AI_AGENT_PATTERN = /claude[-_]?code|anthropic|cursor|copilot|chatgpt|openai|gptbot|perplexity|cohere|codeium|windsurf|tabnine|sourcegraph|cody/i;

// Trailing-slash duplicates split pageview counts and dilute SEO signals across
// two URLs for the same page. Redirect the trailing-slash variants to their
// canonical (non-trailing-slash) paths so analytics and search engines see one.
const TRAILING_SLASH_REDIRECTS = new Map([
	['/Pricing/', '/Pricing'],
	['/UsingSeal/', '/UsingSeal'],
	['/GettingStarted/', '/GettingStarted'],
]);

function resolveRedirect(request) {
	const url = new URL(request.url);
	const canonical = TRAILING_SLASH_REDIRECTS.get(url.pathname);
	if (!canonical) return null;
	url.pathname = canonical;
	return url.toString();
}

function detectServerVisitorType(request) {
	const ua = request.headers.get('user-agent') || '';
	const accept = request.headers.get('accept') || '';
	if (AI_AGENT_PATTERN.test(ua)) return 'agent';
	if (accept.includes('text/markdown')) return 'agent';
	return null;
}

function trackPlausibleEvent(request, visitorType) {
	const url = new URL(request.url);
	const ua = request.headers.get('user-agent') || '';
	const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || '';

	fetch('https://plausible.io/api/event', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'User-Agent': ua,
			'X-Forwarded-For': ip,
		},
		body: JSON.stringify({
			name: 'pageview',
			domain: 'seal-docs.wal.app',
			url: url.toString(),
			referrer: request.headers.get('referer') || '',
			props: { visitor_type: visitorType },
		}),
	}).catch(() => {});
}

export const config = {
	matcher: [
		'/((?!_next|api|static|img|fonts|favicon).*)',
	],
};

export default async function middleware(request) {
	// Consolidate trailing-slash duplicates before any tracking so the pageview
	// is attributed to the canonical URL rather than the redirected one.
	const redirectTo = resolveRedirect(request);
	if (redirectTo) {
		return Response.redirect(redirectTo, 301);
	}

	const visitorType = detectServerVisitorType(request);
	if (visitorType === 'agent') {
		trackPlausibleEvent(request, visitorType);
	}
	return;
}
