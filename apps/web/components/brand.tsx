"use client";

import Image from "next/image";
import { cn } from "@/lib/utils";

export function Brand({ collapsed = false, className }: { collapsed?: boolean; className?: string }) {
  if (collapsed) {
    return (
      <div className={cn("flex items-center justify-center select-none", className)} aria-label="Gödel Tally">
        <Image
          src="/favicon-light.svg"
          alt="gödel"
          width={28}
          height={28}
          priority
          className="size-7 object-contain dark:hidden"
        />
        <Image
          src="/favicon-dark.svg"
          alt="gödel"
          width={28}
          height={28}
          priority
          className="hidden size-7 object-contain dark:block"
        />
      </div>
    );
  }

  return (
    <div className={cn("inline-flex items-center gap-2 select-none", className)} aria-label="Gödel Tally">
      <Image
        src="/godel-tally-light.svg"
        alt="Gödel Tally"
        width={157}
        height={32}
        priority
        className="h-8 w-auto object-contain dark:hidden"
      />
      <Image
        src="/godel-tally-dark.svg"
        alt="Gödel Tally"
        width={157}
        height={32}
        priority
        className="hidden h-8 w-auto object-contain dark:block"
      />
    </div>
  );
}
