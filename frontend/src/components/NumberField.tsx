import { useId } from "react";
import { NumberField as BaseNumberField } from "@base-ui/react/number-field";
import {
  FormControl,
  IconButton,
  InputAdornment,
  InputLabel,
  OutlinedInput,
  SvgIcon,
} from "@mui/material";

// Let FormControl detect an initially filled input, as in the official MUI demo.
function SSRInitialFilled(_: BaseNumberField.Root.Props) {
  return null;
}
SSRInitialFilled.muiName = "Input";

export function NumberField({
  label,
  size = "medium",
  ...props
}: Pick<
  BaseNumberField.Root.Props,
  "name" | "defaultValue" | "min" | "max" | "disabled" | "required"
> & { label: string; size?: "small" | "medium" }) {
  const id = useId();
  return (
    <BaseNumberField.Root
      {...props}
      step={1}
      smallStep={1}
      format={{ maximumFractionDigits: 0 }}
      render={(rootProps, state) => (
        <FormControl
          ref={rootProps.ref}
          disabled={state.disabled}
          required={state.required}
          variant="outlined"
          size={size}
        >
          {rootProps.children}
        </FormControl>
      )}
    >
      <SSRInitialFilled {...props} />
      <InputLabel htmlFor={id}>{label}</InputLabel>
      <BaseNumberField.Input
        id={id}
        render={(inputProps, state) => (
          <OutlinedInput
            label={label}
            inputRef={inputProps.ref}
            value={state.inputValue}
            onBlur={inputProps.onBlur}
            onChange={inputProps.onChange}
            onKeyUp={inputProps.onKeyUp}
            onKeyDown={inputProps.onKeyDown}
            onFocus={inputProps.onFocus}
            slotProps={{ input: inputProps }}
            endAdornment={
              <InputAdornment
                position="end"
                sx={{
                  flexDirection: "column",
                  maxHeight: "unset",
                  alignSelf: "stretch",
                  borderLeft: "1px solid",
                  borderColor: "divider",
                  ml: 0,
                  "& button": { py: 0, flex: 1, borderRadius: 0.5 },
                }}
              >
                <BaseNumberField.Increment
                  tabIndex={0}
                  aria-label={`Increase ${label}`}
                  render={
                    <IconButton
                      type="button"
                      size={size}
                      aria-label={`Increase ${label}`}
                    />
                  }
                >
                  <SvgIcon
                    fontSize={size}
                    sx={{ transform: "translateY(2px)" }}
                  >
                    <path d="m7.41 15.41 4.59-4.58 4.59 4.58L18 14l-6-6-6 6z" />
                  </SvgIcon>
                </BaseNumberField.Increment>
                <BaseNumberField.Decrement
                  tabIndex={0}
                  aria-label={`Decrease ${label}`}
                  render={
                    <IconButton
                      type="button"
                      size={size}
                      aria-label={`Decrease ${label}`}
                    />
                  }
                >
                  <SvgIcon
                    fontSize={size}
                    sx={{ transform: "translateY(-2px)" }}
                  >
                    <path d="M7.41 8.59 12 13.17l4.59-4.58L18 10l-6 6-6-6z" />
                  </SvgIcon>
                </BaseNumberField.Decrement>
              </InputAdornment>
            }
            sx={{ pr: 0 }}
          />
        )}
      />
    </BaseNumberField.Root>
  );
}
