export type LocalCalendarDate = {
  date: string;
  files: {
    filename: string;
    path: string;
    size_bytes: number;
    modified_at: string;
    extension: string;
  }[];
};
