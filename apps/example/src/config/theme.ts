import {adaptive, defineTheme} from '@hzblj/kara-ui'

/**
 * An amber accent, the icon's, apart from the Nitro Wallet's emerald and the Airgap Example's indigo so the examples
 * never pass for each other: every accent token is set in one place, and the Android seed moves with them.
 */
export const theme = defineTheme({
  colors: {
    border: {accent: '#d97706'},
    content: {accent: adaptive({dark: '#fbbf24', light: '#b45309'})},
    fill: {
      accent: {
        base: adaptive({dark: '#d9770633', light: '#fdf0dc'}),
        disabled: adaptive({dark: '#d977061f', light: '#f8dcb4'}),
        primary: '#d97706',
      },
    },
    shadow: {btn: {accent: {ring: adaptive({dark: '#d9770600', light: '#f6c98a'})}}},
  },
  materialSeed: '#d97706',
})
