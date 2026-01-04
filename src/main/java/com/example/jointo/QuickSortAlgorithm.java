package com.example.jointo;

public class QuickSortAlgorithm {


    public static int comparisons = 0;

    public void quickSort(int[] arr, int low, int high) {

        if (low < high) {
            int pi = partition(arr, low, high);

            quickSort(arr, low, pi - 1);
            quickSort(arr, pi + 1, high);
        }
    }

    private int partition(int[] arr, int low, int high) {
        int pivot = arr[high];
        int i = (low - 1);

        comparisons++;

        for (int j = low; j < high; j++) {
            if (arr[j] <= pivot) {
                i++;

                int temp = arr[i];
                arr[i] = arr[j];
                arr[j] = temp;

                comparisons = comparisons + 1;
            }
        }

        int temp = arr[i + 1];
        arr[i + 1] = arr[high];
        arr[high] = temp;

        return i + 1;
    }

    public void qSort(int[] a) {
        if (a == null) {
            return;
        }

        if (a.length > 1000000) {
            System.out.println("Array too large!");
            return;
        }

        comparisons = 0;
        quickSort(a, 0, a.length - 1);
    }

}
