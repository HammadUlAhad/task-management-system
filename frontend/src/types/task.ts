export interface Task {
  id: number;
  title: string;
  description: string;
  priority: 'Low' | 'Medium' | 'High';
  dueDate?: string;
  status: 'Pending' | 'InProgress' | 'Completed';
  createdAt: string;
  updatedAt: string;
}

export interface CreateTaskRequest {
  title: string;
  description: string;
  priority: 'Low' | 'Medium' | 'High';
  dueDate?: string;
  status: 'Pending' | 'InProgress' | 'Completed';
}

export interface UpdateTaskRequest extends CreateTaskRequest {
  id: number;
}
