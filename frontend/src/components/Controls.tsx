import { useId, useState } from "react";
import { IconButton, Menu, MenuItem, SvgIcon, Tooltip } from "@mui/material";

const paths = {
  refresh:
    "M17.65 6.35A7.95 7.95 0 0 0 12 4a8 8 0 1 0 7.75 10h-2.08A6 6 0 1 1 12 6c1.66 0 3.14.69 4.22 1.78L13 11h7V4z",
  logout:
    "M10 17v-3h7v-4h-7V7l-5 5zM3 3h9v2H3v14h9v2H1V3zm13 0h7v18h-7v-2h5V5h-5z",
  dark: "M9.37 5.51A7 7 0 0 0 18.49 14.63 7 7 0 1 1 9.37 5.51M12 2a10 10 0 1 0 10 10c0-.46-.04-.92-.1-1.37A8 8 0 0 1 13.37 2.1 10 10 0 0 0 12 2",
  light:
    "M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10M11 1h2v4h-2zm0 18h2v4h-2zM1 11h4v2H1zm18 0h4v2h-4zM4.22 2.81l2.83 2.83-1.41 1.41-2.83-2.83zm12.73 14.14 2.83 2.83 1.41-1.41-2.83-2.83zM2.81 19.78l2.83-2.83 1.41 1.41-2.83 2.83zm14.14-14.14 2.83-2.83 1.41 1.41-2.83 2.83z",
  copy: "M16 1H4v14h2V3h10zm3 4H8v18h13V5zm0 16H10V7h9z",
  edit: "M3 17.25V21h3.75L17.81 9.94l-3.75-3.75zM20.71 7.04a1 1 0 0 0 0-1.41l-2.34-2.34a1 1 0 0 0-1.41 0l-1.83 1.83 3.75 3.75z",
  delete:
    "M6 19a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V7H6zm13-15h-3.5l-1-1h-5l-1 1H5v2h14z",
  more: "M12 4a2 2 0 1 0 0 4 2 2 0 0 0 0-4m0 6a2 2 0 1 0 0 4 2 2 0 0 0 0-4m0 6a2 2 0 1 0 0 4 2 2 0 0 0 0-4",
};
type Glyph = keyof typeof paths;
export function Glyph({ name }: { name: Glyph }) {
  return (
    <SvgIcon>
      <path d={paths[name]} />
    </SvgIcon>
  );
}
export function IconAction({
  label,
  icon,
  disabled,
  onClick,
}: {
  label: string;
  icon: Glyph;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <Tooltip title={label}>
      <span>
        <IconButton aria-label={label} disabled={disabled} onClick={onClick}>
          <Glyph name={icon} />
        </IconButton>
      </span>
    </Tooltip>
  );
}
export function ActionMenu({
  label,
  disabled,
  items,
}: {
  label: string;
  disabled?: boolean;
  items: { label: string; icon?: Glyph; onClick: () => void }[];
}) {
  const id = useId();
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  return (
    <>
      <Tooltip title={label}>
        <span>
          <IconButton
            aria-label={label}
            disabled={disabled}
            aria-haspopup="menu"
            aria-controls={anchor ? id : undefined}
            aria-expanded={!!anchor}
            onClick={(e) => setAnchor(e.currentTarget)}
          >
            <Glyph name="more" />
          </IconButton>
        </span>
      </Tooltip>
      <Menu
        id={id}
        anchorEl={anchor}
        open={!!anchor}
        onClose={() => setAnchor(null)}
        slotProps={{ list: { "aria-label": label } }}
      >
        {items.map((item) => (
          <MenuItem
            key={item.label}
            disabled={disabled}
            onClick={() => {
              setAnchor(null);
              item.onClick();
            }}
          >
            {item.icon && <Glyph name={item.icon} />}
            {item.label}
          </MenuItem>
        ))}
      </Menu>
    </>
  );
}
