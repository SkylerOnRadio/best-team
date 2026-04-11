export type ActivityBucket = {
  timeLabel: string;
  count: number;
};

export type BubbleGroup =
  | "Access"
  | "Integrity"
  | "Data"
  | "Availability"
  | "Recon";

export type BubblePoint = {
  id: string;
  label: string;
  group: BubbleGroup;
  xValue: number;
  yValue: number;
  sizeValue: number;
  hits: number;
  failures: number;
  tags: string[];
};

export const bubblePalette: Record<BubbleGroup, string> = {
  Access: "#22d3ee",
  Integrity: "#f97316",
  Data: "#a3e635",
  Availability: "#f43f5e",
  Recon: "#c084fc",
};
