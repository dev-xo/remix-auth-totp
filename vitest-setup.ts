import { installGlobals } from '@remix-run/node'

/**
 * Remix relies on browser API's such as fetch that are not natively available in Node.js,
 * you may find that unit tests fail without these globals, when running with tools such as Jest.
 */
installGlobals()
