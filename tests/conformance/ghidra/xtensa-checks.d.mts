import type { XtensaElfMetadata } from "../../../src/domain/binaryTargetTypes.js";

export const XTENSA_LANGUAGE: "Xtensa:LE:32:default";
export const XTENSA_COMPILER_SPEC: "default";
export interface XtensaReadelfFacts {
  xtensa: XtensaElfMetadata;
  symbols: Record<string, string>;
  descriptor: string;
}
export function parseXtensaReadelf(
  text: string,
  names: readonly string[],
): XtensaReadelfFacts;
export function inspectXtensaReadelf(
  path: string,
  names: readonly string[],
): Promise<XtensaReadelfFacts & { command: string; version: string }>;
export function assertXtensaFixtureInstructions(
  instructions: Record<"entry" | "l32r" | "call8" | "retw", unknown>,
  addresses: { leaf: string; literal: string },
): void;
export function assertXtensaFixturePseudocode(
  entry: string,
  leaf: string,
  values: { literal: number; addend: number },
): void;
export function assertXtensaCFixturePseudocode(
  entry: string,
  scale: string,
  values: { global: string; factor: number; constant: number },
): void;
export function assertXtensaCall0FixtureInstructions(
  instructions: Record<"l32r" | "call0" | "ret" | "callx0", unknown>,
  addresses: { leaf: string; literal: string },
): void;
export function xtensaCall0RomKeptValue(
  code: string,
  values: { rom: number; kept: number },
): "folded" | "before-call";
export function xtensaCall0KeptValue(
  entry: string,
  values: { literal: number; kept: number },
): "folded" | "before-call";
export function assertXtensaCall0FixturePseudocode(
  entry: string,
  leaf: string,
  values: { literal: number; addend: number; kept: number },
): void;
export function assertXtensaCall0CFixturePseudocode(
  entry: string,
  scale: string,
  values: { mask: number; factor: number; constant: number },
): void;
