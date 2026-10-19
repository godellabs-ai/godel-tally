import * as React from "react";

import { cn } from "@/lib/utils";

function Table({ className, ...props }: React.ComponentProps<"table">) {
  return <div className="custom-scrollbar relative w-full overflow-auto"><table className={cn("w-full caption-bottom text-sm", className)} {...props} /></div>;
}
function TableHeader({ className, ...props }: React.ComponentProps<"thead">) { return <thead className={cn("border-border bg-muted/30 [&_tr]:border-b", className)} {...props} />; }
function TableBody({ className, ...props }: React.ComponentProps<"tbody">) { return <tbody className={cn("divide-y divide-border/60 [&_tr:last-child]:border-0", className)} {...props} />; }
function TableRow({ className, ...props }: React.ComponentProps<"tr">) { return <tr className={cn("cursor-pointer border-b border-border/40 transition-colors hover:bg-muted/15", className)} {...props} />; }
function TableHead({ className, ...props }: React.ComponentProps<"th">) { return <th className={cn("px-6 py-3.5 text-left align-middle text-[11px] font-bold uppercase tracking-wider text-muted-foreground", className)} {...props} />; }
function TableCell({ className, ...props }: React.ComponentProps<"td">) { return <td className={cn("px-6 py-3.5 align-middle", className)} {...props} />; }

export { Table, TableHeader, TableBody, TableRow, TableHead, TableCell };
