import { FieldType } from '../proto';

export interface TemplateField {
  id: string;
  type: FieldType;
  name: string;
  label: string;
  required: boolean;
  placeholder: string;
  helpText: string;
  maxLength?: number;
  pattern?: string;
  numberConfig?: {
    min: number;
    max: number;
    step: number;
  };
  options?: string[];
}

export interface Template {
  name: string;
  description: string;
  category: string;
  fields: TemplateField[];
}

export const TEMPLATES: Template[] = [
  {
    name: "Employee Feedback",
    description: "Gather anonymous workplace and management feedback from your team.",
    category: "HR",
    fields: [
      {
        id: "satisfaction",
        type: FieldType.RADIO,
        name: "workplace_rating",
        label: "How would you rate your overall workplace satisfaction?",
        required: true,
        placeholder: "",
        helpText: "Select one option.",
        options: ["1 - Very Dissatisfied", "2 - Dissatisfied", "3 - Neutral", "4 - Satisfied", "5 - Very Satisfied"]
      },
      {
        id: "department",
        type: FieldType.SELECT,
        name: "department",
        label: "Which department do you work in?",
        required: false,
        placeholder: "Select department...",
        helpText: "Optional",
        options: ["Engineering", "Product", "Design", "Marketing", "Sales", "HR/Operations", "Other"]
      },
      {
        id: "positives",
        type: FieldType.TEXTAREA,
        name: "positives",
        label: "What is working well in your current role or team?",
        required: true,
        placeholder: "Tell us about what you enjoy or what keeps you motivated...",
        helpText: ""
      },
      {
        id: "improvements",
        type: FieldType.TEXTAREA,
        name: "improvements",
        label: "What could be improved to make your work better?",
        required: true,
        placeholder: "Share constructive suggestions or blockers you face...",
        helpText: ""
      }
    ]
  },
  {
    name: "Event Feedback",
    description: "Collect attendee satisfaction data and suggestions for future events.",
    category: "Events",
    fields: [
      {
        id: "overall_rating",
        type: FieldType.RADIO,
        name: "overall_rating",
        label: "Overall, how would you rate the event?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["1 - Poor", "2 - Fair", "3 - Good", "4 - Very Good", "5 - Excellent"]
      },
      {
        id: "favorite_session",
        type: FieldType.TEXT,
        name: "favorite_session",
        label: "What was your favorite session or speaker?",
        required: false,
        placeholder: "Title or speaker name",
        helpText: ""
      },
      {
        id: "recommend",
        type: FieldType.CHECKBOX,
        name: "recommend",
        label: "Would you recommend this event to a friend or colleague?",
        required: false,
        placeholder: "",
        helpText: ""
      },
      {
        id: "suggestions",
        type: FieldType.TEXTAREA,
        name: "suggestions",
        label: "Do you have any other comments or suggestions for improvements?",
        required: false,
        placeholder: "Share your thoughts...",
        helpText: ""
      }
    ]
  },
  {
    name: "Course Evaluation",
    description: "Get feedback on academic courses, lectures, or training programs.",
    category: "Education",
    fields: [
      {
        id: "difficulty",
        type: FieldType.RADIO,
        name: "difficulty",
        label: "How would you rate the difficulty of this course?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["Too Easy", "Appropriate", "Too Hard"]
      },
      {
        id: "instructor_quality",
        type: FieldType.RADIO,
        name: "instructor_quality",
        label: "How would you rate the quality of the instruction?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["1 - Poor", "2 - Fair", "3 - Satisfactory", "4 - Good", "5 - Excellent"]
      },
      {
        id: "most_valuable",
        type: FieldType.TEXT,
        name: "most_valuable",
        label: "What was the most valuable part of the course?",
        required: false,
        placeholder: "Topics, assignments, or labs",
        helpText: ""
      },
      {
        id: "improvements",
        type: FieldType.TEXTAREA,
        name: "improvements",
        label: "How could the course content or structure be improved?",
        required: false,
        placeholder: "Constructive feedback...",
        helpText: ""
      }
    ]
  },
  {
    name: "Product Feedback",
    description: "Collect user feedback to drive product features and improvements.",
    category: "Product",
    fields: [
      {
        id: "satisfaction",
        type: FieldType.RADIO,
        name: "satisfaction",
        label: "How satisfied are you with our product?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["1 - Very Dissatisfied", "2 - Dissatisfied", "3 - Neutral", "4 - Satisfied", "5 - Very Satisfied"]
      },
      {
        id: "most_used",
        type: FieldType.SELECT,
        name: "most_used",
        label: "Which feature do you use the most?",
        required: false,
        placeholder: "Select feature...",
        helpText: "",
        options: ["Dashboard", "Analytics", "Settings", "Billing", "Integrations", "API"]
      },
      {
        id: "missing_features",
        type: FieldType.TEXTAREA,
        name: "missing_features",
        label: "What features are missing that you'd like to see?",
        required: false,
        placeholder: "Describe the functionality and why you need it...",
        helpText: ""
      },
      {
        id: "nps",
        type: FieldType.NUMBER,
        name: "nps",
        label: "How likely are you to recommend us to a friend? (0-10)",
        required: true,
        placeholder: "Score 0 to 10",
        helpText: "",
        numberConfig: { min: 0, max: 10, step: 1 }
      }
    ]
  },
  {
    name: "Team Pulse Check",
    description: "Run a quick satisfaction and health check for your team.",
    category: "Management",
    fields: [
      {
        id: "morale",
        type: FieldType.RADIO,
        name: "morale",
        label: "How is your morale today?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["1 - Low", "2 - Mediocre", "3 - Good", "4 - Great", "5 - Excellent"]
      },
      {
        id: "workload",
        type: FieldType.RADIO,
        name: "workload",
        label: "How do you feel about your current workload?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["I have too little to do", "My workload is manageable", "I am overwhelmed"]
      },
      {
        id: "communication",
        type: FieldType.RADIO,
        name: "communication",
        label: "How would you rate communication within the team?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["1 - Poor", "2 - Subpar", "3 - Clear & transparent", "4 - Excellent"]
      },
      {
        id: "blockers",
        type: FieldType.TEXT,
        name: "blockers",
        label: "What is your biggest blocker or concern right now?",
        required: false,
        placeholder: "Describe blockers...",
        helpText: "Optional"
      }
    ]
  },
  {
    name: "App Feedback",
    description: "Gather feedback from your mobile or web app users.",
    category: "Product",
    fields: [
      {
        id: "rating",
        type: FieldType.RADIO,
        name: "app_rating",
        label: "How would you rate our app?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["1 Star", "2 Stars", "3 Stars", "4 Stars", "5 Stars"]
      },
      {
        id: "device",
        type: FieldType.SELECT,
        name: "device_os",
        label: "What device or OS are you using?",
        required: true,
        placeholder: "Select OS...",
        helpText: "",
        options: ["iOS (iPhone)", "Android", "Web Browser (Desktop)", "Web Browser (Mobile)", "Other"]
      },
      {
        id: "positives",
        type: FieldType.TEXTAREA,
        name: "app_positives",
        label: "What do you like most about the app?",
        required: false,
        placeholder: "Speed, design, specific features...",
        helpText: ""
      },
      {
        id: "bugs",
        type: FieldType.TEXTAREA,
        name: "app_bugs",
        label: "Did you encounter any bugs or issues? (Optional)",
        required: false,
        placeholder: "Describe the issue and steps to reproduce...",
        helpText: ""
      }
    ]
  },
  {
    name: "College Feedback",
    description: "Gather students' anonymous thoughts on courses, facilities, and campus life.",
    category: "Education",
    fields: [
      {
        id: "department",
        type: FieldType.SELECT,
        name: "college_department",
        label: "Which department or major are you in?",
        required: true,
        placeholder: "Select major/dept...",
        helpText: "",
        options: ["Computer Science / IT", "Engineering", "Natural Sciences", "Arts & Humanities", "Business & Economics", "Social Sciences", "Other"]
      },
      {
        id: "satisfaction",
        type: FieldType.RADIO,
        name: "college_satisfaction",
        label: "Overall, how satisfied are you with your college experience?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["1 - Very Dissatisfied", "2 - Dissatisfied", "3 - Neutral", "4 - Satisfied", "5 - Very Satisfied"]
      },
      {
        id: "facilities",
        type: FieldType.CHECKBOX,
        name: "facilities_ok",
        label: "Are you satisfied with the campus library and study spaces?",
        required: false,
        placeholder: "",
        helpText: ""
      },
      {
        id: "suggestions",
        type: FieldType.TEXTAREA,
        name: "college_suggestions",
        label: "What is one thing the college administration could improve immediately?",
        required: true,
        placeholder: "Share your thoughts...",
        helpText: ""
      }
    ]
  },
  {
    name: "Exit Interview",
    description: "Gather parting insights from departing employees to improve retention.",
    category: "HR",
    fields: [
      {
        id: "reason",
        type: FieldType.SELECT,
        name: "primary_reason_leaving",
        label: "What is your primary reason for leaving?",
        required: true,
        placeholder: "Select reason...",
        helpText: "",
        options: ["Better career opportunity", "Career change", "Compensation & benefits", "Work environment/culture", "Management issues", "Personal/Family reasons", "Other"]
      },
      {
        id: "recommend",
        type: FieldType.RADIO,
        name: "recommend_company",
        label: "Would you recommend this company as a good place to work?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["No", "Maybe/With reservations", "Yes, absolutely"]
      },
      {
        id: "feedback",
        type: FieldType.TEXTAREA,
        name: "exit_interview_feedback",
        label: "What advice would you give to management to make this team better?",
        required: true,
        placeholder: "Constructive advice...",
        helpText: ""
      }
    ]
  },
  {
    name: "Customer Satisfaction",
    description: "Measure customer happiness with support, services, or interactions.",
    category: "Support",
    fields: [
      {
        id: "csat",
        type: FieldType.RADIO,
        name: "csat_score",
        label: "How would you rate your overall satisfaction with the support you received?",
        required: true,
        placeholder: "",
        helpText: "",
        options: ["1 - Very Dissatisfied", "2 - Dissatisfied", "3 - Neutral", "4 - Satisfied", "5 - Very Satisfied"]
      },
      {
        id: "resolved",
        type: FieldType.CHECKBOX,
        name: "issue_resolved",
        label: "Was your issue fully resolved?",
        required: true,
        placeholder: "",
        helpText: ""
      },
      {
        id: "agent_rating",
        type: FieldType.SELECT,
        name: "agent_helpfulness",
        label: "How helpful and polite was our support representative?",
        required: false,
        placeholder: "Choose rating...",
        helpText: "",
        options: ["Unhelpful/Impolite", "Neutral", "Very helpful & polite"]
      },
      {
        id: "comments",
        type: FieldType.TEXTAREA,
        name: "csat_comments",
        label: "Is there anything else we could have done to make your experience better?",
        required: false,
        placeholder: "Your comments...",
        helpText: ""
      }
    ]
  },
  {
    name: "Company Performance Metrics",
    description: "Collect quarterly key performance indicators (KPIs) and operational metrics from team leads.",
    category: "Analytics",
    fields: [
      {
        id: "revenue_growth",
        type: FieldType.NUMBER,
        name: "revenue_growth_rate",
        label: "Quarterly Revenue Growth Rate (%)",
        required: true,
        placeholder: "e.g. 15",
        helpText: "Enter growth rate percentage.",
        numberConfig: { min: -100, max: 1000, step: 0.1 }
      },
      {
        id: "active_users",
        type: FieldType.NUMBER,
        name: "monthly_active_users",
        label: "Current Monthly Active Users (MAU)",
        required: true,
        placeholder: "e.g. 50000",
        helpText: "Total active users for the current month.",
        numberConfig: { min: 0, max: 100000000, step: 1 }
      },
      {
        id: "cac",
        type: FieldType.NUMBER,
        name: "customer_acquisition_cost",
        label: "Customer Acquisition Cost (CAC) in ₹",
        required: true,
        placeholder: "e.g. 2500",
        helpText: "Average acquisition cost per customer.",
        numberConfig: { min: 0, max: 100000, step: 1 }
      },
      {
        id: "nps",
        type: FieldType.NUMBER,
        name: "net_promoter_score",
        label: "Net Promoter Score (NPS) (0-10)",
        required: true,
        placeholder: "0 to 10",
        helpText: "",
        numberConfig: { min: 0, max: 10, step: 1 }
      }
    ]
  },
  {
    name: "Student Performance Tracker",
    description: "Track and aggregate anonymous student grades, attendance, and exam performance metrics.",
    category: "Education",
    fields: [
      {
        id: "attendance_rate",
        type: FieldType.NUMBER,
        name: "attendance_rate",
        label: "Attendance Rate (%)",
        required: true,
        placeholder: "0 to 100",
        helpText: "Percentage of classes attended.",
        numberConfig: { min: 0, max: 100, step: 1 }
      },
      {
        id: "midterm_score",
        type: FieldType.NUMBER,
        name: "midterm_exam_score",
        label: "Midterm Exam Score (out of 100)",
        required: true,
        placeholder: "0 to 100",
        helpText: "",
        numberConfig: { min: 0, max: 100, step: 0.5 }
      },
      {
        id: "final_score",
        type: FieldType.NUMBER,
        name: "final_exam_score",
        label: "Final Exam Score (out of 100)",
        required: true,
        placeholder: "0 to 100",
        helpText: "",
        numberConfig: { min: 0, max: 100, step: 0.5 }
      },
      {
        id: "homework_completion",
        type: FieldType.NUMBER,
        name: "homework_completion_rate",
        label: "Homework Completion Rate (%)",
        required: true,
        placeholder: "0 to 100",
        helpText: "",
        numberConfig: { min: 0, max: 100, step: 1 }
      }
    ]
  }
];
