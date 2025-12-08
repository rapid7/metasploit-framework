import { greet } from './actions';

export default async function Home() {
  const greeting = await greet("World");
  
  return (
    <main style={{ padding: '2rem', fontFamily: 'system-ui' }}>
      <h1>{greeting}</h1>
    </main>
  );
}
