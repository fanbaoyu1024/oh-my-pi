import { describe, expect, test } from "bun:test";
import { decodeKiroEventStream } from "../src/providers/kiro-eventstream";

function preludeStream(totalLength: number, headersLength: number): ReadableStream<Uint8Array> {
	const prelude = new Uint8Array(8);
	const view = new DataView(prelude.buffer);
	view.setUint32(0, totalLength, false);
	view.setUint32(4, headersLength, false);
	return new ReadableStream<Uint8Array>({
		start(controller) {
			controller.enqueue(prelude);
			controller.close();
		},
	});
}

async function consume(source: ReadableStream<Uint8Array>): Promise<void> {
	for await (const _message of decodeKiroEventStream(source)) {
		// A prelude-only stream cannot produce a complete message.
	}
}

describe("Kiro EventStream allocation limits", () => {
	test("rejects an oversized declared frame before buffering its payload", async () => {
		await expect(consume(preludeStream(16 * 1024 * 1024 + 1, 0))).rejects.toThrow(
			"Kiro event stream frame length 16777217 exceeds maximum 16777216",
		);
	});

	test("rejects an oversized declared header block before buffering it", async () => {
		await expect(consume(preludeStream(128 * 1024 + 17, 128 * 1024 + 1))).rejects.toThrow(
			"Kiro event stream header length 131073 exceeds maximum 131072",
		);
	});
});
