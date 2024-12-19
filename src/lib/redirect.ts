export function redirect(url: string, init: ResponseInit | number = 302) {
	let responseInit = init;

	if (typeof responseInit === "number") {
		responseInit = { status: responseInit };
	} else if (typeof responseInit.status === "undefined") {
		responseInit.status = 302;
	}

	const headers = new Headers(responseInit.headers);
	headers.set("Location", url);

	return new Response(null, { ...responseInit, headers });
}