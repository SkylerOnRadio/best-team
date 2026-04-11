export type LocalCalendarDate = {
  date: string;
  files: {
    filename: string;
    url: string;
    path?: string;
    size_bytes?: number;
    modified_at?: string;
    extension?: string;
  }[];
};
