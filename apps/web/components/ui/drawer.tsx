"use client";

import * as React from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";

import { cn } from "@/lib/utils";

const Drawer = DialogPrimitive.Root;
const DrawerTrigger = DialogPrimitive.Trigger;
const DrawerClose = DialogPrimitive.Close;
const DrawerPortal = DialogPrimitive.Portal;

interface DrawerContentProps
  extends React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content> {
  /** Embedded hosts can use this marker to provide their own drawer navigation rail. */
  showTOC?: boolean;
}

function DrawerContent({
  className,
  children,
  showTOC = false,
  ...props
}: DrawerContentProps) {
  return (
    <DrawerPortal>
      <DialogPrimitive.Overlay
        className={cn(
          "fixed inset-0 z-50 bg-slate-950/40 backdrop-blur-[1.5px] transition-all",
          "data-[state=open]:animate-in data-[state=open]:fade-in-0",
          "data-[state=closed]:animate-out data-[state=closed]:fade-out-0",
        )}
      />
      <DialogPrimitive.Content
        data-drawer-toc={showTOC ? "enabled" : undefined}
        style={{ width: "clamp(760px, 60vw, 1080px)", maxWidth: "100vw" }}
        className={cn(
          "fixed inset-y-0 right-0 z-50 flex h-full flex-col overflow-hidden border-l border-border/80 bg-[#f7f7fb] text-foreground shadow-[0_22px_70px_rgba(28,24,44,0.22)] outline-none dark:bg-[#181821]",
          "data-[state=open]:animate-in data-[state=open]:slide-in-from-right data-[state=open]:duration-300",
          "data-[state=closed]:animate-out data-[state=closed]:slide-out-to-right",
          className,
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close className="ring-offset-background focus:ring-ring absolute right-2.5 top-2.5 z-30 flex size-7 items-center justify-center rounded-md p-1 opacity-70 transition-opacity hover:bg-muted hover:opacity-100 focus:outline-none focus:ring-2">
          <X className="size-4" />
          <span className="sr-only">Close</span>
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DrawerPortal>
  );
}

function DrawerTitle({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>) {
  return (
    <DialogPrimitive.Title
      className={cn("min-w-0 wrap-anywhere text-base font-semibold", className)}
      {...props}
    />
  );
}

function DrawerDescription({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Description>) {
  return (
    <DialogPrimitive.Description
      className={cn("min-w-0 wrap-anywhere text-sm text-muted-foreground", className)}
      {...props}
    />
  );
}

export {
  Drawer,
  DrawerTrigger,
  DrawerClose,
  DrawerContent,
  DrawerTitle,
  DrawerDescription,
};
