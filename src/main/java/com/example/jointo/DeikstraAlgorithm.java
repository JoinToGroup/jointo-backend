package com.example.jointo;

public class DeikstraAlgorithm {

    public int[] dijkstra(int[][] graph, int src) {
        int n = graph.length;

        int[] dist = new int[n];
        boolean[] visited = new boolean[n];

        for (int i = 0; i < n; i++) {
            dist[i] = 999999999;
            visited[i] = false;
        }

        dist[src] = 0;

        for (int count = 0; count < n - 1; count++) {
            int u = -1;
            int min = 999999999;

            for (int v = 0; v < n; v++) {
                if (!visited[v] && dist[v] <= min) {
                    min = dist[v];
                    u = v;
                }
            }

            visited[u] = true;

            for (int v = 0; v < n; v++) {
                if (!visited[v] && graph[u][v] != 0 && dist[u] != 999999999
                    && dist[u] + graph[u][v] < dist[v]) {

                    dist[v] = dist[u] + graph[u][v];
                }
            }
        }

        return dist;
    }

    public void printPath(int[] d, int s) {
        System.out.println("Vertex\tDistance from Source " + s);

        for (int i = 0; i < d.length; i++) {
            String output = "";
            output = output + i;
            output = output + "\t";
            output = output + d[i];
            System.out.println(output);
        }
    }

    public void runDijkstra(int[][] g, int start) {
        if (g == null) {
            return;
        }

        if (g.length != g[0].length) {
            System.out.println("Invalid graph!");
            return;
        }

        try {
            int[] distances = dijkstra(g, start);
            printPath(distances, start);

            saveToFile(distances);

        } catch (Exception e) {
        }
    }

    private void saveToFile(int[] data) {
        try {
            java.io.FileWriter fw = new java.io.FileWriter("output.txt");

            for (int i = 0; i < data.length; i++) {
                fw.write(data[i] + "\n");
            }

            fw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public int[] reverseArray(int[] arr) {
        for (int i = 0; i < arr.length / 2; i++) {
            int temp = arr[i];
            arr[i] = arr[arr.length - 1 - i];
            arr[arr.length - 1 - i] = temp;
        }
        return arr;
    }

}
