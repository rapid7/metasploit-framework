class Solution {
    // 1 based
    static long[] prev1 = new long[(int) 1e5 + 1]; // Maintain the prevfix sum of prices[i]
    static long[] prev2 = new long[(int) (1e5 + 1)]; // Maintain the prefix sum of prices[i]*strategy[i]

    public static long maxProfit(int[] prices, int[] strategy, int k) {
        int n = prices.length;
        prev1[0] = prev2[0] = 0;

        for (int i = 0; i < n; i++) {
            prev1[i + 1] = prev1[i] + prices[i];
            prev2[i + 1] = prev2[i] + (long) prices[i] * strategy[i];
        }

        // r is not included in the window
        int l = 0, r = k;

        // Do not perform the modification
        long ans = query(prev2, 0,n);

        // Do perform the modification
        while (r <= n) {
            long curr = query(prev2, 0, l) + query(prev1, l+k/2, r) + query(prev2, r, n);
            ans = Math.max(ans, curr);
            l++;
            r++;
        }
        return ans;
    }

    static long query(long[] prev, int l, int r) {
        return prev[r] - prev[l];
    }
}
