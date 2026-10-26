import {useAppTheme} from '@hzblj/kara-ui'
import {Stack} from 'expo-router'

import {Providers} from '../src/providers'

const RootStack = () => {
  const theme = useAppTheme()

  return (
    <Stack
      screenOptions={{
        contentStyle: {backgroundColor: theme.color('surface.base')},
        headerBackButtonDisplayMode: 'minimal',
        headerLargeTitle: true,
      }}
    >
      <Stack.Screen name="index" options={{title: 'Vault'}} />
    </Stack>
  )
}

export default function RootLayout() {
  return (
    <Providers>
      <RootStack />
    </Providers>
  )
}
