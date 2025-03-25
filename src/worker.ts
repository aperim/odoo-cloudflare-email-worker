/* eslint-disable no-console */
/**
 * Email Processor Module (TypeScript refactor)
 *
 * Supports an extensible chain of processor classes:
 * 1. Spam checking
 * 2. Parsing
 * 3. Domain-collapsing (optional)
 * 4. Subaddressing
 * 5. Pre-delivery (re-serialise)
 * 6. Delivery to Odoo CRM
 *
 * Each processor can reject the message or continue. Errors in a processor
 * do not cause cascading termination, but explicit rejections do.
 *
 * Author: Troy Kelly
 * Contact: troy@aperim.com
 *
 * Code History:
 * - Created on 2024-10-21 by Troy Kelly (TK)
 * - TK Updated SpamFilter to include sender name analysis for Gmail addresses.
 * - TK Modified on 2024-10-22 to fix response handling and add error capturing.
 * - TK Refactored 2025-01-16 to support extensible processor classes.
 */

/**
 * Describes the result of processing within each pipeline processor.
 */
interface ProcessingResult {
	canContinue: boolean;
	rejectReason?: string;
}

/**
 * Data structure containing parsed email headers and body.
 */
interface ParsedEmail {
	headers: Array<{ raw: string; name: string; value: string }>;
	body: Uint8Array;
}

/**
 * Aggregates all information shared across the pipeline.
 */
interface EmailPipelineContext {
	message: ForwardableEmailMessage;
	env: Env;
	rawEmail: Uint8Array | null;
	parsedEmail: ParsedEmail | null;
	finalRawEmail: Uint8Array | null;
}

/**
 * Asynchronously converts a ReadableStream into a Uint8Array.
 *
 * @param stream The stream to convert.
 * @param streamSize The expected size of the stream.
 * @return The resulting bytes from the stream.
 */
async function streamToArrayBuffer(stream: ReadableStream<Uint8Array>, streamSize: number): Promise<Uint8Array> {
	const result = new Uint8Array(streamSize);
	let bytesRead = 0;
	const reader = stream.getReader();

	while (true) {
		const { done, value } = await reader.read();
		if (done || !value) {
			break;
		}
		result.set(value, bytesRead);
		bytesRead += value.length;
	}

	return result;
}

/**
 * Converts an ArrayBuffer/Uint8Array to a base64 encoded string.
 *
 * @param arrayBuffer The buffer to convert.
 * @return The base64 encoded string.
 */
function base64ArrayBuffer(arrayBuffer: ArrayBuffer | Uint8Array): string {
	const encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	let base64 = '';
	const bytes = arrayBuffer instanceof Uint8Array ? arrayBuffer : new Uint8Array(arrayBuffer);
	const byteLength = bytes.byteLength;
	const byteRemainder = byteLength % 3;
	const mainLength = byteLength - byteRemainder;

	for (let i = 0; i < mainLength; i += 3) {
		const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
		const a = (chunk & 0xff0000) >> 16;
		const b = (chunk & 0xff00) >> 8;
		const c = chunk & 0xff;

		base64 += encodings[a >> 2];
		base64 += encodings[((a & 3) << 4) | (b >> 4)];
		base64 += encodings[((b & 15) << 2) | (c >> 6)];
		base64 += encodings[c & 63];
	}

	if (byteRemainder === 1) {
		const a = bytes[mainLength];
		base64 += encodings[a >> 2];
		base64 += encodings[(a & 3) << 4];
		base64 += '==';
	} else if (byteRemainder === 2) {
		const a = bytes[mainLength];
		const b = bytes[mainLength + 1];
		base64 += encodings[a >> 2];
		base64 += encodings[((a & 3) << 4) | (b >> 4)];
		base64 += encodings[(b & 15) << 2];
		base64 += '=';
	}

	return base64;
}

/**
 * Base class for all email processors.
 *
 * Processors must implement the .process() method and return an object:
 * { canContinue: boolean, rejectReason?: string }
 *
 * If canContinue is false, the pipeline stops and the email is rejected with rejectReason.
 * If a processor throws an error, the pipeline logs it and continues to the next processor.
 */
class BaseEmailProcessor {
	protected context: EmailPipelineContext;

	/**
	 * Creates a new BaseEmailProcessor.
	 *
	 * @param context The pipeline context shared across processors.
	 */
	constructor(context: EmailPipelineContext) {
		this.context = context;
	}

	/**
	 * Process method to be overridden by subclasses.
	 *
	 * @return The result of processing.
	 */
	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	async process(): Promise<ProcessingResult> {
		return { canContinue: true };
	}
}

/**
 * Processor for spam checks (blocklists, Gmail name analysis, spam subject keywords).
 */
class SpamCheckProcessor extends BaseEmailProcessor {
	/**
	 * @override
	 */
	async process(): Promise<ProcessingResult> {
		const { message } = this.context;

		const blocklist = ['spam@example.com', 'blocked@example.com'];
		const fromHeader = message.headers.get('from') || '';

		// Extract the sender's email from the 'From' header
		const emailMatch = fromHeader.match(/<([^>]+)>/);
		const senderEmail = emailMatch ? emailMatch[1] : fromHeader;
		const senderEmailLower = senderEmail.toLowerCase();

		// Check if sender is in blocklist
		if (blocklist.includes(senderEmailLower)) {
			console.log('[SpamCheckProcessor] Rejected message because sender is in blocklist.');
			return {
				canContinue: false,
				rejectReason: 'Sender is blocked.',
			};
		}

		// Gmail logic
		if (senderEmailLower.endsWith('@gmail.com')) {
			// Extract name if possible
			const nameMatch = fromHeader.match(/^(.*)<[^>]+>/);
			const senderName = nameMatch ? nameMatch[1].trim() : '';

			if (!senderName) {
				console.log('[SpamCheckProcessor] Rejected message because sender name is missing.');
				return {
					canContinue: false,
					rejectReason: 'Sender name is missing.',
				};
			}

			// Check if the sender name is a continuous string of letters/numbers
			if (/^[A-Za-z0-9]+$/.test(senderName)) {
				const letters = senderName.replace(/[^A-Za-z]/g, '');
				const totalLetters = letters.length;

				if (totalLetters >= 8) {
					const uppercaseLetters = senderName.replace(/[^A-Z]/g, '');
					const lowercaseLetters = senderName.replace(/[^a-z]/g, '');

					const uppercaseCount = uppercaseLetters.length;
					const lowercaseCount = lowercaseLetters.length;

					const uppercasePercentage = (uppercaseCount / totalLetters) * 100;
					const lowercasePercentage = (lowercaseCount / totalLetters) * 100;

					if (
						uppercasePercentage >= 40 &&
						uppercasePercentage <= 60 &&
						lowercasePercentage >= 40 &&
						lowercasePercentage <= 60
					) {
						console.log('[SpamCheckProcessor] Rejected message because sender name resembles spam pattern.');
						return {
							canContinue: false,
							rejectReason: 'Sender name resembles spam pattern.',
						};
					}
				}
			}
		}

		// Check for spam keywords in subject
		const spamKeywords = [
			'viagra',
			'prince',
			'winner',
			'quick discussion',
			'intro call',
			'exploratory call',
			'domaine expirera',
			'market trends',
			'collaboration',
			'website builder',
			'running ads',
			'website error',
			'content error',
			'full proposal',
			'cost your business',
			'send you a quote',
			'get a sample',
			'market research',
			'confirm your delivery',
			're: proposal',
			'urgent notice',
			'tax discrepancy',
		];
		const subject = message.headers.get('subject') || '';
		const lowercaseSubject = subject.toLowerCase();
		for (const keyword of spamKeywords) {
			if (lowercaseSubject.includes(keyword)) {
				console.log('[SpamCheckProcessor] Rejected message because it contains spam keywords.');
				return {
					canContinue: false,
					rejectReason: 'Message contains spam keywords.',
				};
			}
		}

		// Passed all checks
		console.log('[SpamCheckProcessor] No spam detected, no message changes made.');
		return { canContinue: true };
	}
}

/**
 * Processor that attempts to read and parse the raw email into headers/body.
 * Stores the parsed result in this.context.parsedEmail for subsequent processors.
 */
class ParsingProcessor extends BaseEmailProcessor {
	/**
	 * @override
	 */
	async process(): Promise<ProcessingResult> {
		const { message } = this.context;

		let rawEmail: Uint8Array;
		try {
			rawEmail = await streamToArrayBuffer(message.raw, message.rawSize);
		} catch (error) {
			console.error('ParsingProcessor: No valid raw email data.', error);
			return {
				canContinue: false,
				rejectReason: 'Unable to process email data.',
			};
		}

		this.context.rawEmail = rawEmail;
		const parsed = parseEmail(rawEmail);
		this.context.parsedEmail = parsed;

		console.log('[ParsingProcessor] Raw email parsed into structured form.');
		return { canContinue: true };
	}
}

/**
 * Processor that checks the environment for a special variable defining
 * domain collapse info. For any address in To, Cc, Bcc that matches
 * one of the listed domains, rewrite the entire address to the target.
 *
 * Example env.DOMAIN_COLLAPSE_MAPPING string:
 * "suppliers.example.invalid=suppliers@example.invalid, team.example.invalid=allstaff@example.invalid"
 */
class DomainCollapseProcessor extends BaseEmailProcessor {
	/**
	 * @override
	 */
	async process(): Promise<ProcessingResult> {
		const { env, parsedEmail } = this.context;
		if (!parsedEmail || !parsedEmail.headers) {
			console.log('[DomainCollapseProcessor] No parsed email data available, skipping.');
			return { canContinue: true };
		}

		const domainCollapseStr = env.DOMAIN_COLLAPSE_MAPPING || '';
		if (!domainCollapseStr.trim()) {
			console.log('[DomainCollapseProcessor] No domain collapse mapping defined, skipping.');
			return { canContinue: true };
		}

		let domainMap: Record<string, string>;
		try {
			domainMap = parseDomainCollapseMap(domainCollapseStr);
		} catch (error) {
			console.error('DomainCollapseProcessor: Unable to parse domain collapse map.', error);
			return { canContinue: true };
		}

		if (Object.keys(domainMap).length === 0) {
			console.log('[DomainCollapseProcessor] Domain collapse map is empty, skipping.');
			return { canContinue: true };
		}

		let changedCount = 0;
		const updatedHeaders = parsedEmail.headers.map((header) => {
			const hName = header.name.toLowerCase();
			if (['to', 'cc', 'bcc'].includes(hName)) {
				const addresses = splitAddresses(header.value);
				const transformed = addresses.map((addrStr) => {
					const { displayName, address } = parseAddress(addrStr);
					const domainPart = address.split('@')[1] || '';
					const domainLower = domainPart.toLowerCase();
					if (domainMap[domainLower]) {
						changedCount++;
						return formatAddress(displayName, domainMap[domainLower]);
					}
					return addrStr;
				});
				const newValue = transformed.join(', ');
				return {
					...header,
					value: newValue,
					raw: `${header.name}: ${newValue}`,
				};
			}
			return header;
		});

		if (updatedHeaders && this.context.parsedEmail) this.context.parsedEmail.headers = updatedHeaders;

		if (changedCount > 0) {
			console.log(`[DomainCollapseProcessor] Rewrote ${changedCount} addresses in To/Cc/Bcc headers.`);
		} else {
			console.log('[DomainCollapseProcessor] No domain collapses applied.');
		}
		return { canContinue: true };
	}
}

/**
 * Processor that handles subaddressing (e.g. local+tag@domain).
 * If a subaddress tag is found, it is removed from the local part,
 * and that tag is optionally prepended to the Subject in brackets.
 */
class SubaddressingProcessor extends BaseEmailProcessor {
	/**
	 * @override
	 */
	async process(): Promise<ProcessingResult> {
		const { parsedEmail } = this.context;
		if (!parsedEmail || !parsedEmail.headers) {
			console.log('[SubaddressingProcessor] No parsed email data available, skipping.');
			return { canContinue: true };
		}

		const { subaddressTag, updatedHeaders } = processSubaddressing(parsedEmail.headers);
		const finalHeaders = prependSubjectTag(updatedHeaders, subaddressTag);

		if (finalHeaders && this.context.parsedEmail) this.context.parsedEmail.headers = finalHeaders;
		if (subaddressTag) {
			console.log(
				`[SubaddressingProcessor] Removed subaddress tag: ${subaddressTag}, updated "To" header and possibly adjusted subject.`
			);
		} else {
			console.log('[SubaddressingProcessor] No subaddressing found.');
		}
		return { canContinue: true };
	}
}

/**
 * Processor that re-serialises the updated headers/body back to raw form,
 * storing it in this.context.finalRawEmail for final delivery.
 */
class PreDeliveryProcessor extends BaseEmailProcessor {
	/**
	 * @override
	 */
	async process(): Promise<ProcessingResult> {
		const { parsedEmail } = this.context;
		if (!parsedEmail) {
			console.error('PreDeliveryProcessor: No parsed email to re-serialise.');
			return { canContinue: false, rejectReason: 'No parsed email to deliver.' };
		}

		const finalRawEmail = reSerialiseEmail(parsedEmail.headers, parsedEmail.body);
		this.context.finalRawEmail = finalRawEmail;

		console.log('[PreDeliveryProcessor] Re-serialised updated email.');
		return { canContinue: true };
	}
}

/**
 * Processor that delivers the final raw email to Odoo CRM.
 * If delivery fails, it rejects the message.
 */
class DeliveryProcessor extends BaseEmailProcessor {
	/**
	 * @override
	 */
	async process(): Promise<ProcessingResult> {
		const { env, finalRawEmail } = this.context;
		if (!finalRawEmail) {
			console.error('DeliveryProcessor: No final raw email to deliver.');
			return { canContinue: false, rejectReason: 'No final email data to deliver.' };
		}

		console.log('[DeliveryProcessor] Sending email to CRM...');

		const options = {
			database: env.ODOO_DATABASE || 'company',
			userid: env.ODOO_USERID || '2',
			password: env.ODOO_PASSWORD || 'password',
			host: env.ODOO_HOST || 'crm.example.com',
			port: env.ODOO_PORT || '443',
			protocol: env.ODOO_PROTOCOL || 'https',
		};

		const crm = new CrmServerHandler(options);

		try {
			await crm.sendEmail(finalRawEmail);
			console.log('[DeliveryProcessor] Email successfully handed off to CRM.');
		} catch (error) {
			console.error('DeliveryProcessor:', error);
			const msg = error instanceof Error ? error.message : String(error);
			return { canContinue: false, rejectReason: `Unable to deliver to CRM. ${msg}` };
		}

		return { canContinue: true };
	}
}

/**
 * CRM server handler, specifically for Odoo via XML-RPC.
 */
class CrmServerHandler {
	private options: {
		database: string;
		userid: string;
		password: string;
		host: string;
		port: string;
		protocol: string;
	};

	/**
	 * Creates a new CrmServerHandler with connection options.
	 *
	 * @param options CRM connection options.
	 */
	constructor(options: {
		database: string;
		userid: string;
		password: string;
		host: string;
		port: string;
		protocol: string;
	}) {
		this.options = options;
	}

	/**
	 * Sends raw email data to Odoo via XML-RPC.
	 *
	 * @param rawEmail The raw email data.
	 */
	async sendEmail(rawEmail: Uint8Array): Promise<void> {
		const url = `${this.options.protocol}://${this.options.host}:${this.options.port}/xmlrpc/2/object`;

		const xml = `<?xml version="1.0"?>
<methodCall>
  <methodName>execute_kw</methodName>
  <params>
    <param><value><string>${this.options.database}</string></value></param>
    <param><value><int>${this.options.userid}</int></value></param>
    <param><value><string>${this.options.password}</string></value></param>
    <param><value><string>mail.thread</string></value></param>
    <param><value><string>message_process</string></value></param>
    <param>
      <value>
        <array>
          <data>
            <value><boolean>0</boolean></value>
            <value><base64>${base64ArrayBuffer(rawEmail)}</base64></value>
          </data>
        </array>
      </value>
    </param>
    <param><value><struct></struct></value></param>
  </params>
</methodCall>`;

		const headers = { 'Content-Type': 'application/xml' };
		const fetchOptions: RequestInit = {
			method: 'POST',
			headers,
			body: xml,
		};

		try {
			const response = await fetch(url, fetchOptions);
			const data = await response.text();
			await this.validateResponse(response, data);
		} catch (error) {
			console.error('Error during CRM communication:', {
				errorMessage: error instanceof Error ? error.message : String(error),
				stack: error instanceof Error ? error.stack : null,
				requestUrl: url,
				requestOptions: fetchOptions,
				environment: {
					database: this.options.database,
					userid: this.options.userid,
					host: this.options.host,
					port: this.options.port,
					protocol: this.options.protocol,
				},
			});
			const msg = error instanceof Error ? error.message : String(error);
			throw new Error(`Unable to communicate with CRM server: ${msg}`);
		}
	}

	/**
	 * Validates the CRM server response, robustly capturing the faultString from Odoo.
	 *
	 * @param response The fetch Response object.
	 * @param data The response body text.
	 */
	private async validateResponse(response: Response, data: string): Promise<void> {
		if (!response.ok) {
			console.error(`HTTP Error: ${response.status} ${response.statusText}`);
			console.error(
				`[CrmServerHandler] Full response data (base64): ${base64ArrayBuffer(new TextEncoder().encode(data))}`
			);
			throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
		}

		if (data.includes('<fault>')) {
			const faultStringRegex = /<name>\s*faultString\s*<\/name>\s*<value>\s*<string>\s*([\s\S]*?)\s*<\/string>/i;
			const faultStringMatch = data.match(faultStringRegex);
			const faultString = faultStringMatch ? faultStringMatch[1].trim() : 'Unknown fault';

			if (faultString.includes('ValueError: No possible route found for incoming message')) {
				console.error(`CRM route error: ${faultString}`);
				throw new Error('Mailbox not found or no valid route. Please check the mail alias or CRM configuration.');
			}

			console.error(`Fault response from API: ${faultString}`);
			console.error(
				`[CrmServerHandler] Full response data (base64): ${base64ArrayBuffer(new TextEncoder().encode(data))}`
			);
			throw new Error(`CRM Error: ${faultString}`);
		}

		const intMatch = data.match(/<int>\s*(\d+)\s*<\/int>/i);
		const booleanMatch = data.match(/<boolean>\s*(\d)\s*<\/boolean>/i);

		if (intMatch) {
			const recordId = parseInt(intMatch[1], 10);
			if (recordId > 0) {
				console.log(`Successfully processed. Record ID: ${recordId}`);
			} else {
				console.warn('Received non-positive record ID from CRM.');
				throw new Error('Invalid record ID received from CRM.');
			}
		} else if (booleanMatch) {
			const booleanValue = booleanMatch[1];
			console.log(`CRM response received. Boolean value: ${booleanValue}`);

			if (booleanValue === '0') {
				console.error('Email was rejected by CRM with boolean value 0.');
				throw new Error('Email rejected by CRM.');
			} else {
				console.log('Email accepted by CRM with boolean true.');
			}
		} else {
			console.warn('[CrmServerHandler] Unexpected response format from CRM.');
			console.warn(
				`[CrmServerHandler] Full response data (base64): ${base64ArrayBuffer(new TextEncoder().encode(data))}`
			);
			throw new Error('Unexpected response format from CRM.');
		}
	}
}

/* ------------------------- */
/* RFC 5322 style utilities  */
/* ------------------------- */

/**
 * Parse the headers and body from raw email data.
 * Merges folded header lines with their preceding lines. Returns an object
 * with { headers, body }, where headers is an array of { raw, name, value },
 * and body is a Uint8Array.
 *
 * @param rawEmail The raw email data.
 * @return An object with { headers, body }.
 */
function parseEmail(rawEmail: Uint8Array): ParsedEmail {
	const text = new TextDecoder('utf-8', { fatal: false, ignoreBOM: false }).decode(rawEmail);
	const allLines = text.replace(/\r?\n/g, '\n').split('\n');

	const headers: Array<{ raw: string; name: string; value: string }> = [];
	let bodyLines: string[] = [];
	let isHeaderSection = true;
	let currentHeaderName = '';
	let currentHeaderValue = '';

	for (const line of allLines) {
		if (isHeaderSection) {
			if (line.trim() === '') {
				if (currentHeaderName) {
					headers.push({
						raw: `${currentHeaderName}: ${currentHeaderValue}`,
						name: currentHeaderName,
						value: currentHeaderValue,
					});
				}
				isHeaderSection = false;
				continue;
			}

			if (/^[ \t]/.test(line)) {
				currentHeaderValue += ` ${line.trim()}`;
			} else {
				if (currentHeaderName) {
					headers.push({
						raw: `${currentHeaderName}: ${currentHeaderValue}`,
						name: currentHeaderName,
						value: currentHeaderValue,
					});
				}
				const idx = line.indexOf(':');
				if (idx !== -1) {
					currentHeaderName = line.substring(0, idx).trim();
					currentHeaderValue = line.substring(idx + 1).trim();
				} else {
					currentHeaderName = line.trim();
					currentHeaderValue = '';
				}
			}
		} else {
			bodyLines.push(line);
		}
	}

	if (currentHeaderName && isHeaderSection) {
		headers.push({
			raw: `${currentHeaderName}: ${currentHeaderValue}`,
			name: currentHeaderName,
			value: currentHeaderValue,
		});
	}

	const bodyText = bodyLines.join('\n');
	const encodedBody = new TextEncoder().encode(bodyText);

	return {
		headers,
		body: encodedBody,
	};
}

/**
 * Splits a string containing possibly multiple email addresses into an array
 * of address strings. This is a simplistic approach and does not fully comply with RFC 5322.
 *
 * @param headerValue The header value to split.
 * @return The array of address strings.
 */
function splitAddresses(headerValue: string): string[] {
	const parts: string[] = [];
	let current = '';
	let inQuotes = false;
	for (let i = 0; i < headerValue.length; i++) {
		const c = headerValue[i];
		if (c === '"') {
			inQuotes = !inQuotes;
			current += c;
		} else if (c === ',' && !inQuotes) {
			parts.push(current.trim());
			current = '';
		} else {
			current += c;
		}
	}
	if (current.trim()) {
		parts.push(current.trim());
	}
	return parts;
}

/**
 * Parses a single address string into display name and address.
 *
 * @param addrStr The raw address string.
 * @return An object with { displayName, address }.
 */
function parseAddress(addrStr: string): { displayName: string; address: string } {
	const angleMatch = addrStr.match(/^(.*)<([^>]+)>.*$/);
	if (angleMatch) {
		const rawName = angleMatch[1].trim();
		const rawAddr = angleMatch[2].trim();
		return { displayName: stripQuotes(rawName), address: rawAddr };
	}
	return { displayName: '', address: addrStr.trim() };
}

/**
 * Re-serialises address as "Name <address>" or just "address" if no display name.
 *
 * @param displayName Name portion
 * @param address Address portion
 * @return A combined string.
 */
function formatAddress(displayName: string, address: string): string {
	if (displayName) {
		return `"${displayName}" <${address}>`;
	}
	return address;
}

/**
 * Removes surrounding quotes if present.
 *
 * @param str Input string
 * @return Unquoted string
 */
function stripQuotes(str: string): string {
	let trimmed = str;
	if (
		(trimmed.startsWith('"') && trimmed.endsWith('"')) ||
		(trimmed.startsWith("'") && trimmed.endsWith("'"))
	) {
		trimmed = trimmed.slice(1, -1);
	}
	return trimmed;
}

/**
 * Parse domain collapse map from a single string. May be comma- or semicolon-separated.
 * Example: "suppliers.example.invalid=suppliers@example.invalid,team.example.invalid=allstaff@example.invalid"
 *
 * @param str The domain map string.
 * @return Mapping of domain -> targetAddress
 */
function parseDomainCollapseMap(str: string): Record<string, string> {
	const separators = /[,;]+/;
	const map: Record<string, string> = {};
	const entries = str.split(separators).map((s) => s.trim()).filter(Boolean);
	for (const entry of entries) {
		const eqIndex = entry.indexOf('=');
		if (eqIndex === -1) {
			continue;
		}
		const domainPart = entry.substring(0, eqIndex).trim().toLowerCase();
		const targetAddress = entry.substring(eqIndex + 1).trim();
		if (domainPart && targetAddress) {
			map[domainPart] = targetAddress;
		}
	}
	return map;
}

/**
 * Removes subaddressing (e.g. local+tag@domain) from "To" header
 * and returns a subaddressTag if found. Only modifies the first "To" header encountered.
 *
 * @param headers Original array of headers (with raw/name/value).
 * @return Object containing subaddressTag and updated headers.
 */
function processSubaddressing(
	headers: Array<{ raw: string; name: string; value: string }>
): {
	subaddressTag: string;
	updatedHeaders: Array<{ raw: string; name: string; value: string }>;
} {
	let subaddressTag = '';
	const updatedHeaders = headers.map((h) => {
		if (h.name.toLowerCase() === 'to') {
			const addressParts = splitAddresses(h.value);
			const updatedAddressParts = addressParts.map((addr) => {
				const { displayName, address } = parseAddress(addr);
				const plusRegex = /^([^+]+)\+([^@]+)@(.*)$/;
				const match = address.match(plusRegex);
				if (match) {
					const localPart = match[1];
					const tag = match[2];
					const domainPart = match[3];
					if (!subaddressTag) {
						subaddressTag = tag;
					}
					const newValue = `${localPart}@${domainPart}`;
					return formatAddress(displayName, newValue);
				}
				return addr;
			});
			const newValue = updatedAddressParts.join(', ');
			return {
				...h,
				value: newValue,
				raw: `${h.name}: ${newValue}`,
			};
		}
		return h;
	});

	return { subaddressTag, updatedHeaders };
}

/**
 * Prepends "[tag]" to the Subject header if not already present.
 *
 * @param headers Array of headers (with raw/name/value).
 * @param tag The subaddressTag to prepend.
 * @return A new array with updated subject if needed.
 */
function prependSubjectTag(
	headers: Array<{ raw: string; name: string; value: string }>,
	tag: string
): Array<{ raw: string; name: string; value: string }> {
	if (!tag) {
		return headers;
	}
	const bracketTag = `[${tag}]`;
	return headers.map((h) => {
		if (h.name.toLowerCase() === 'subject') {
			if (!h.value.toLowerCase().includes(bracketTag.toLowerCase())) {
				const newValue = `${bracketTag} ${h.value}`;
				return {
					...h,
					value: newValue,
					raw: `${h.name}: ${newValue}`,
				};
			}
		}
		return h;
	});
}

/**
 * Re-serialises headers + body into a Uint8Array with CRLF line endings.
 *
 * @param headers The updated headers
 * @param body The email body
 * @return A Uint8Array of the final raw message
 */
function reSerialiseEmail(
	headers: Array<{ raw: string; name: string; value: string }>,
	body: Uint8Array
): Uint8Array {
	const headerLines = headers.map((h) => `${h.name}: ${h.value}`);
	const textHead = headerLines.join('\r\n');
	const textFinal = `${textHead}\r\n\r\n${new TextDecoder().decode(body)}`;
	return new TextEncoder().encode(textFinal);
}

/**
 * Default export with the main email handler function.
 */
export default {
	/**
	 * Cloudflare Worker-style email handler.
	 *
	 * @param message The email message to process.
	 * @param env Environment variables (e.g. ODOO credentials, domain collapse mapping).
	 * @param ctx Execution context.
	 */
	async email(message: ForwardableEmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
		const context: EmailPipelineContext = {
			message,
			env,
			rawEmail: null,
			parsedEmail: null,
			finalRawEmail: null,
		};

		const processors = [
			new SpamCheckProcessor(context),
			new ParsingProcessor(context),
			new DomainCollapseProcessor(context),
			new SubaddressingProcessor(context),
			new PreDeliveryProcessor(context),
			new DeliveryProcessor(context),
		];

		for (const processor of processors) {
			try {
				const result = await processor.process();
				if (!result.canContinue) {
					const constructorRef = processor.constructor as Function & { name?: string };
					const constructorName = constructorRef.name || 'Unknown';
					console.warn(
						`Email rejected by ${constructorName}: ${result.rejectReason || 'No reason'}`
					);
					message.setReject(result.rejectReason || 'Message rejected by processor.');
					return;
				}
			} catch (err) {
				const constructorRef = processor.constructor as Function & { name?: string };
				const constructorName = constructorRef.name || 'Unknown';
				console.error(`Error in ${constructorName}`, err);
			}
		}

		// If we reach here successfully, the DeliveryProcessor didn't reject or fail.
		console.log('Email processed successfully through all processors.');
	},
} satisfies ExportedHandler<Env>;