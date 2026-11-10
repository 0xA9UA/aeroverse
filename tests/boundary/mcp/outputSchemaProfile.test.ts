import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { z } from "zod";
import { expect, it } from "vitest";

import {
  TOOL_CONTRACTS,
  toolContract,
} from "../../../src/contracts/toolContracts.js";
import { EvidenceMcpServer } from "../../../src/server/EvidenceMcpServer.js";
import { toolRegistrationOptions } from "../../../src/server/toolRegistrationOptions.js";
import { createToolResultDelivery } from "../../../src/server/toolResult.js";
import type { ToolContract } from "../../../src/contracts/toolContractTypes.js";
import { FULL_CATALOG_IDENTITY } from "../../../src/catalogIdentity.js";
import {
  COMPACT_INPUT_SCHEMA_BUDGET_BYTES,
  compactPresentationForMcpInputSchemaProfile,
  type McpInputSchemaProfile,
} from "../../../src/config/mcpInputSchemaProfile.js";
import { advertisedInputJsonSchema } from "../../../src/contracts/toolSchemaMetadata.js";

const createServer = (
  omitOutputSchemas: boolean,
  inputProfile?: McpInputSchemaProfile,
) =>
  new EvidenceMcpServer(
    { name: "output-schema-fixture", version: "1" },
    { capabilities: {} },
    undefined,
    createToolResultDelivery(10 * 1024 * 1024),
    compactPresentationForMcpInputSchemaProfile(inputProfile),
    omitOutputSchemas,
  );

it("omits only output schema advertisements and keeps canonical MCP output validation", async () => {
  const server = createServer(true, "full");
  expect(server.catalogIdentity.digests.combined_sha256).not.toBe(
    FULL_CATALOG_IDENTITY.digests.combined_sha256,
  );
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "schema-profile-test", version: "1" });
  const contract = {
    ...toolContract("comment"),
    name: "output_schema_fixture",
    inputSchema: z.strictObject({}),
    outputSchema: z.strictObject({ value: z.string() }),
  } satisfies ToolContract;
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async () => ({
      content: [{ type: "text" as const, text: "fixture" }],
      structuredContent: { value: "complete" },
    }),
  );
  const invalidContract = {
    ...contract,
    name: "invalid_output_schema_fixture",
  } satisfies ToolContract;
  server.registerTool(
    invalidContract.name,
    toolRegistrationOptions(invalidContract),
    async () => ({
      content: [{ type: "text" as const, text: "invalid fixture" }],
      structuredContent: { value: 42 },
    }),
  );

  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    const tools = (await client.listTools()).tools;
    expect(tools).toHaveLength(2);
    expect(tools.every((tool) => tool.outputSchema === undefined)).toBe(true);
    const success = await client.callTool({
      name: contract.name,
      arguments: {},
    });
    expect(success.isError).not.toBe(true);
    expect(success.structuredContent).toEqual({ value: "complete" });
    const invalid = await client.callTool({
      name: invalidContract.name,
      arguments: {},
    });
    expect(invalid.isError).toBe(true);
    expect(invalid.content).toEqual([
      expect.objectContaining({
        type: "text",
        text: expect.stringContaining("Output validation error"),
      }),
    ]);
  } finally {
    await client.close();
    await server.close();
  }
});

it("keeps the complete catalog below one megabyte with default compact inputs and output schemas off", async () => {
  expect(compactPresentationForMcpInputSchemaProfile(undefined)).toEqual({
    budgetBytes: COMPACT_INPUT_SCHEMA_BUDGET_BYTES,
  });
  const measure = async (
    omitOutputSchemas: boolean,
    inputProfile?: McpInputSchemaProfile,
  ) => {
    const server = createServer(omitOutputSchemas, inputProfile);
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "catalog-size-test", version: "1" });
    for (const contract of TOOL_CONTRACTS)
      server.registerTool(
        contract.name,
        toolRegistrationOptions(contract),
        async () => ({
          content: [{ type: "text" as const, text: "unused" }],
        }),
      );
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const listed = await client.listTools();
      return {
        bytes: Buffer.byteLength(JSON.stringify(listed), "utf8"),
        tools: listed.tools,
      };
    } finally {
      await client.close();
      await server.close();
    }
  };

  const outputSchemasFull = await measure(false);
  const outputSchemasOff = await measure(true);
  const explicitFullInputs = await measure(true, "full");
  expect(outputSchemasFull.bytes).toBeGreaterThan(1024 * 1024);
  expect(outputSchemasOff.bytes).toBeLessThan(1024 * 1024);
  expect(outputSchemasOff.bytes).toBeLessThan(outputSchemasFull.bytes);
  expect(outputSchemasOff.bytes).toBeLessThan(explicitFullInputs.bytes);
  expect(outputSchemasOff.tools).toEqual(
    outputSchemasFull.tools.map(
      ({ outputSchema: _outputSchema, ...tool }) => tool,
    ),
  );
  const fullTools = new Map(
    explicitFullInputs.tools.map((tool) => [tool.name, tool]),
  );
  expect(fullTools.size).toBe(TOOL_CONTRACTS.length);
  for (const contract of TOOL_CONTRACTS) {
    const tool = fullTools.get(contract.name);
    expect(tool?.inputSchema, contract.name).toEqual(
      advertisedInputJsonSchema(contract),
    );
    expect(tool?.outputSchema, contract.name).toBeUndefined();
  }
});
